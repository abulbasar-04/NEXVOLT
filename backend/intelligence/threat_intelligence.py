import hashlib
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
from dotenv import load_dotenv


logger = logging.getLogger(__name__)
BACKEND_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_DIR / ".env")

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")
PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
OPENPHISH_FEED_URL = os.getenv(
    "OPENPHISH_FEED_URL",
    "https://openphish.com/feed.txt",
)
REQUEST_TIMEOUT = 5.0
MAX_OPENPHISH_FEED_BYTES = 8_000_000
OPENPHISH_CACHE_SECONDS = 900

_openphish_lock = threading.Lock()
_openphish_cache = {"expires_at": 0.0, "urls": None, "checked_at": None}

THREAT_RECOMMENDATIONS = {
    "malware_distribution": (
        "Do not download or execute content from this URL. Block the indicator "
        "and follow your malware response process."
    ),
    "phishing": (
        "Do not enter credentials or payment information. Verify the destination "
        "through a trusted channel."
    ),
    "credential_harvesting": (
        "Do not submit credentials. Block the URL and notify affected users if "
        "they may have interacted with it."
    ),
    "suspicious_redirect": (
        "Do not follow the redirect chain until each destination is independently "
        "verified."
    ),
    "malicious_domain": (
        "Avoid connecting to this domain and investigate the indicator with your "
        "security team."
    ),
    "unknown": (
        "Treat this report as unclassified and review the source evidence before "
        "taking action."
    ),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_url(url: str) -> str:
    """Canonicalize URL form without dropping path, query, or case-sensitive data."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("A valid URL is required.")
    value = url.strip()
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only absolute HTTP and HTTPS URLs can be checked.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials cannot be checked.")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("URL contains an invalid port.") from error

    hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if not hostname:
        raise ValueError("URL contains an invalid hostname.")
    scheme = parsed.scheme.lower()
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port and not (scheme == "http" and port == 80 or scheme == "https" and port == 443):
        netloc = f"{netloc}:{port}"

    # Fragments are client-side only and are not sent to threat-feed URL lookups.
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def normalize_domain(url_or_domain: str) -> str:
    if not isinstance(url_or_domain, str) or not url_or_domain.strip():
        raise ValueError("A URL or domain is required.")
    candidate = url_or_domain.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlsplit(candidate)
    if (
        parsed.scheme.lower() not in ("http", "https")
        or parsed.username
        or parsed.password
        or not parsed.hostname
    ):
        raise ValueError("A valid URL or domain is required.")
    try:
        _ = parsed.port
        return parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as error:
        raise ValueError("Domain contains an invalid hostname.") from error


def _base_result(source: str, url: str, status: str, **extra) -> dict:
    return {
        "source": source,
        "queried_url": url,
        "status": status,
        "malicious": False,
        "category": None,
        "confidence": None,
        "confidence_note": None,
        "checked_at": _now(),
        "reported_at": None,
        "details": None,
        "error": None,
        **extra,
    }


def _threat_category(source: str, threat=None, tags=None) -> str:
    tokens = " ".join(
        str(value).lower()
        for value in [threat, *(tags or [])]
        if value
    )
    if any(word in tokens for word in ("credential", "stealer", "login page")):
        return "credential_harvesting"
    if any(word in tokens for word in ("phish", "credential theft")):
        return "phishing"
    if any(word in tokens for word in ("redirector", "redirect", "url forwarding")):
        return "suspicious_redirect"
    if any(word in tokens for word in ("malware", "payload", "botnet", "trojan", "ransomware")):
        return "malware_distribution"
    if source in ("PhishTank", "OpenPhish"):
        return "phishing"
    if source == "URLhaus":
        return "malware_distribution" if threat else "unknown"
    return "unknown"


def _mark_confirmed(result: dict, category: str, details: dict, confidence_note: str) -> dict:
    result.update(
        status="malicious",
        malicious=True,
        category=category,
        confidence="high",
        confidence_note=confidence_note,
        details=details,
        reported_at=details.get("reported_at"),
    )
    return result


def _request_error_result(source: str, url: str, error: Exception) -> dict:
    result = _base_result(source, url, "unavailable")
    if isinstance(error, httpx.TimeoutException):
        result["error"] = f"{source} request timed out."
    elif isinstance(error, httpx.HTTPStatusError):
        result["error"] = f"{source} returned HTTP {error.response.status_code}."
    elif isinstance(error, httpx.RequestError):
        result["error"] = f"Could not connect to {source}."
    else:
        result["status"] = "unknown"
        result["error"] = f"{source} returned an invalid response."
    return result


def check_urlhaus(url: str) -> dict:
    """Check a canonical exact URL against URLhaus."""
    try:
        normalized = normalize_url(url)
    except ValueError as error:
        return _base_result("URLhaus", "", "invalid_input", error=str(error))

    if not URLHAUS_AUTH_KEY:
        return _base_result(
            "URLhaus",
            normalized,
            "unavailable",
            error="URLhaus API key is not configured.",
        )

    try:
        response = httpx.post(
            URLHAUS_API,
            data={"url": normalized},
            headers={"Auth-Key": URLHAUS_AUTH_KEY},
            timeout=REQUEST_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("URLhaus returned a non-object response.")
        query_status = data.get("query_status")
        if query_status == "ok":
            details = {
                "urlhaus_reference": data.get("urlhaus_reference"),
                "url": data.get("url"),
                "url_status": data.get("url_status"),
                "threat": data.get("threat"),
                "date_added": data.get("date_added"),
                "tags": data.get("tags") or [],
                "reporter": data.get("reporter"),
                "reported_at": data.get("date_added"),
            }
            category = _threat_category(
                "URLhaus",
                data.get("threat"),
                data.get("tags") or [],
            )
            result = _base_result("URLhaus", normalized, "malicious")
            return _mark_confirmed(
                result,
                category,
                details,
                "High confidence: URLhaus returned an exact URL match. This is a source rating, not a calibrated probability.",
            )
        if query_status == "no_results":
            return _base_result("URLhaus", normalized, "not_found")
        return _base_result(
            "URLhaus",
            normalized,
            "unknown",
            error="URLhaus returned an unrecognized query status.",
        )
    except httpx.TimeoutException as error:
        return _request_error_result("URLhaus", normalized, error)
    except httpx.HTTPStatusError as error:
        return _request_error_result("URLhaus", normalized, error)
    except httpx.RequestError as error:
        return _request_error_result("URLhaus", normalized, error)
    except (ValueError, TypeError):
        return _base_result(
            "URLhaus",
            normalized,
            "unknown",
            error="Invalid response received from URLhaus.",
        )


def check_phishtank(url: str) -> dict:
    """Check an exact URL using PhishTank's API when credentials are configured."""
    try:
        normalized = normalize_url(url)
    except ValueError as error:
        return _base_result("PhishTank", "", "invalid_input", error=str(error))
    if not PHISHTANK_API_KEY:
        return _base_result(
            "PhishTank",
            normalized,
            "unavailable",
            error="PhishTank API key is not configured.",
        )

    try:
        response = httpx.post(
            PHISHTANK_API,
            data={
                "url": normalized,
                "format": "json",
                "app_key": PHISHTANK_API_KEY,
            },
            headers={"User-Agent": "CYBERNOVA-ThreatIntelligence/1.0"},
            timeout=REQUEST_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("results"), dict):
            return _base_result(
                "PhishTank",
                normalized,
                "unknown",
                error="PhishTank returned an unexpected response.",
            )
        report = data["results"]
        if report.get("in_database") is True:
            verified = report.get("verified") is True
            valid = report.get("valid") is True
            if verified and valid:
                details = {
                    "phish_id": report.get("phish_id"),
                    "phish_detail_page": report.get("phish_detail_page"),
                    "target": report.get("target"),
                    "reported_at": report.get("submission_time"),
                }
                result = _base_result("PhishTank", normalized, "malicious")
                return _mark_confirmed(
                    result,
                    _threat_category("PhishTank"),
                    details,
                    "High confidence: PhishTank marked this exact URL as verified and valid. This is a source rating, not a calibrated probability.",
                )
            return _base_result(
                "PhishTank",
                normalized,
                "unknown",
                details={
                    "phish_id": report.get("phish_id"),
                    "verified": report.get("verified"),
                    "valid": report.get("valid"),
                },
                error="PhishTank record exists but is not confirmed as both verified and valid.",
            )
        if report.get("in_database") is False:
            return _base_result("PhishTank", normalized, "not_found")
        return _base_result(
            "PhishTank",
            normalized,
            "unknown",
            error="PhishTank did not provide a definitive lookup result.",
        )
    except httpx.TimeoutException as error:
        return _request_error_result("PhishTank", normalized, error)
    except httpx.HTTPStatusError as error:
        return _request_error_result("PhishTank", normalized, error)
    except httpx.RequestError as error:
        return _request_error_result("PhishTank", normalized, error)
    except (ValueError, TypeError):
        return _base_result(
            "PhishTank",
            normalized,
            "unknown",
            error="Invalid response received from PhishTank.",
        )


def _fetch_openphish_feed() -> tuple:
    now = time.monotonic()
    if _openphish_cache["urls"] is not None and _openphish_cache["expires_at"] > now:
        return _openphish_cache["urls"], _openphish_cache["checked_at"], None

    with _openphish_lock:
        now = time.monotonic()
        if _openphish_cache["urls"] is not None and _openphish_cache["expires_at"] > now:
            return _openphish_cache["urls"], _openphish_cache["checked_at"], None
        try:
            chunks = bytearray()
            with httpx.stream(
                "GET",
                OPENPHISH_FEED_URL,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": "CYBERNOVA-ThreatIntelligence/1.0"},
            ) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > MAX_OPENPHISH_FEED_BYTES:
                        raise ValueError("OpenPhish feed exceeded the configured size limit.")
            feed_urls = set()
            for line in chunks.decode("utf-8-sig").splitlines():
                candidate = line.strip()
                if not candidate:
                    continue
                try:
                    feed_urls.add(normalize_url(candidate))
                except ValueError:
                    continue
            checked_at = _now()
            _openphish_cache.update({
                "expires_at": time.monotonic() + OPENPHISH_CACHE_SECONDS,
                "urls": feed_urls,
                "checked_at": checked_at,
            })
            return feed_urls, checked_at, None
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.RequestError) as error:
            return None, None, error
        except (UnicodeDecodeError, ValueError, TypeError) as error:
            return None, None, error


def check_openphish(url: str) -> dict:
    """Exact-match lookup against OpenPhish's public community feed."""
    try:
        normalized = normalize_url(url)
    except ValueError as error:
        return _base_result("OpenPhish", "", "invalid_input", error=str(error))

    feed_urls, checked_at, error = _fetch_openphish_feed()
    if feed_urls is None:
        result = _request_error_result("OpenPhish", normalized, error)
        if isinstance(error, ValueError):
            result["status"] = "unknown"
            result["error"] = "OpenPhish feed could not be parsed safely."
        return result

    if normalized in feed_urls:
        result = _base_result("OpenPhish", normalized, "malicious")
        result["checked_at"] = checked_at
        return _mark_confirmed(
            result,
            "phishing",
            {"feed": OPENPHISH_FEED_URL},
            "High confidence: exact URL match in the OpenPhish community feed. This is a source rating, not a calibrated probability.",
        )
    result = _base_result("OpenPhish", normalized, "not_found")
    result["checked_at"] = checked_at
    return result


def _finding_identity(finding: dict) -> tuple:
    indicator = finding.get("normalized_url") or finding.get("normalized_domain")
    category = finding.get("category") or "unknown"
    return indicator, category


def aggregate_threat_results(url: str, sources: dict) -> dict:
    """Aggregate source findings while de-duplicating a threat/category pair."""
    findings_by_key = {}
    source_statuses = []
    checked_at = _now()
    for source_name, source_result in sources.items():
        if not isinstance(source_result, dict):
            continue
        display_source = source_result.get("source") or {
            "urlhaus": "URLhaus",
            "phishtank": "PhishTank",
            "openphish": "OpenPhish",
        }.get(source_name.lower(), source_name)
        status = str(source_result.get("status") or "unknown").lower()
        source_statuses.append(status)
        source_checked_at = source_result.get("checked_at")
        if source_checked_at:
            checked_at = max(checked_at, source_checked_at)
        if status != "malicious" or source_result.get("malicious") is not True:
            continue

        normalized_url = source_result.get("queried_url")
        category = source_result.get("category") or "unknown"
        details = source_result.get("details") or {}
        finding = {
            "id": hashlib.sha256(
                f"{normalized_url}|{category}".encode("utf-8")
            ).hexdigest()[:16],
            "title": f"Confirmed {category.replace('_', ' ')} threat reported.",
            "category": category,
            "severity": "critical",
            "evidence": (
                f"{display_source} reported an exact URL match."
                + (
                    f" Source report date: {source_result.get('reported_at')}."
                    if source_result.get("reported_at")
                    else ""
                )
            ),
            "normalized_url": normalized_url,
            "sources": [display_source],
            "confidence": source_result.get("confidence"),
            "confidence_note": source_result.get("confidence_note"),
            "checked_at": source_result.get("checked_at"),
            "reported_at": source_result.get("reported_at"),
            "source_details": {display_source: details},
            "recommendation": THREAT_RECOMMENDATIONS.get(
                category,
                THREAT_RECOMMENDATIONS["unknown"],
            ),
        }
        key = _finding_identity(finding)
        if key in findings_by_key:
            existing = findings_by_key[key]
            if display_source not in existing["sources"]:
                existing["sources"].append(display_source)
            existing["source_details"][display_source] = details
            if existing.get("reported_at") is None and source_result.get("reported_at"):
                existing["reported_at"] = source_result["reported_at"]
            continue
        findings_by_key[key] = finding

    findings = list(findings_by_key.values())
    confirmed = bool(findings)
    community_result = sources.get("community")
    community_result = (
        community_result if isinstance(community_result, dict) else {}
    )
    community_details = (
        community_result.get("details")
        if isinstance(community_result, dict)
        and isinstance(community_result.get("details"), dict)
        else {}
    )
    has_community_reports = (
        community_result.get("status") in ("unverified", "reviewed")
        or bool(community_details.get("report_count"))
    )
    if confirmed:
        overall_status = "malicious"
    elif has_community_reports:
        overall_status = "partial"
    elif source_statuses and all(status == "not_found" for status in source_statuses):
        overall_status = "not_found"
    elif any(status in ("not_found", "malicious") for status in source_statuses):
        overall_status = "partial"
    elif any(status == "unknown" for status in source_statuses):
        overall_status = "unknown"
    else:
        overall_status = "unavailable"

    return {
        "url": url,
        "status": overall_status,
        "confirmed_malicious": confirmed,
        "checked_at": checked_at,
        "categories": list(dict.fromkeys(item["category"] for item in findings)),
        "findings": findings,
        "sources": sources,
        # Backwards compatibility for current API/UI clients.
        "urlhaus": sources.get("urlhaus") or next(
            (
                source
                for source in sources.values()
                if isinstance(source, dict)
                and str(source.get("source") or "").lower() == "urlhaus"
            ),
            _base_result("URLhaus", url, "unavailable"),
        ),
    }


def _safe_source_lookup(source_key: str, lookup, url: str) -> dict:
    try:
        result = lookup(url)
        if not isinstance(result, dict):
            raise TypeError(f"{source_key} returned a non-object result.")
        return result
    except Exception:
        logger.exception("%s threat-intelligence lookup failed.", source_key)
        return _base_result(
            source_key,
            url,
            "unavailable",
            error=f"{source_key} lookup failed; see server logs for details.",
        )


def check_threat_intelligence(url: str) -> dict:
    """Query enabled threat feeds independently and aggregate their evidence."""
    try:
        normalized_url = normalize_url(url)
    except ValueError as error:
        invalid = _base_result("threat_intelligence", "", "invalid_input", error=str(error))
        invalid.update(
            url=url,
            confirmed_malicious=False,
            checked_at=_now(),
            categories=[],
            findings=[],
            sources={},
            urlhaus=_base_result("URLhaus", "", "invalid_input", error=str(error)),
        )
        return invalid

    try:
        from services.community_reports import lookup_community_reports

        community_result = lookup_community_reports(normalized_url)
    except Exception:
        logger.exception("Community threat report lookup failed.")
        community_result = _base_result(
            "Community reports",
            normalized_url,
            "unavailable",
            error="Community report lookup is unavailable.",
        )

    results = {
        "urlhaus": _safe_source_lookup("URLhaus", check_urlhaus, normalized_url),
        "phishtank": _safe_source_lookup("PhishTank", check_phishtank, normalized_url),
        "openphish": _safe_source_lookup("OpenPhish", check_openphish, normalized_url),
        "community": community_result,
    }
    return aggregate_threat_results(normalized_url, results)
