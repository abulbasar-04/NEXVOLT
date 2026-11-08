from urllib.parse import urlparse
import ipaddress
import re

BRANDS = [
    "paypal", "google", "microsoft", "apple",
    "amazon", "facebook", "instagram", "github",
    "netflix", "telegram", "whatsapp"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account",
    "update", "signin", "password", "banking"
]


def detect_phishing(url: str) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    reasons = []
    findings = []
    score = 0

    def add_finding(title: str, severity: str, evidence: str, points: int) -> None:
        nonlocal score
        score += points
        reasons.append(title)
        findings.append({
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "source": "rule_based",
            "score_impact": points,
        })

    if not host:
        finding = {
            "title": "Invalid hostname",
            "severity": "high",
            "evidence": "The submitted URL does not contain a valid hostname.",
            "source": "rule_based",
            "score_impact": 100,
        }
        return {
            "risk_score": 100,
            "reasons": [finding["title"]],
            "findings": [finding],
        }

    try:
        ipaddress.ip_address(host)
        add_finding(
            "URL uses an IP address instead of a domain.",
            "medium",
            f"Hostname is the IP address {host}.",
            35,
        )
    except ValueError:
        pass

    if "@" in url:
        add_finding(
            "URL contains an @ symbol.",
            "high",
            "The URL contains an @ character, which can obscure the actual hostname.",
            25,
        )

    if host.count("-") >= 2:
        add_finding(
            "Domain contains multiple hyphens.",
            "low",
            f"Hostname {host} contains {host.count('-')} hyphens.",
            15,
        )

    if len(url) > 100:
        add_finding(
            "Unusually long URL.",
            "low",
            f"URL length is {len(url)} characters (heuristic threshold: 100).",
            10,
        )

    if parsed.scheme != "https":
        add_finding(
            "URL does not use HTTPS.",
            "medium",
            f"URL scheme is {parsed.scheme or 'missing'}, not HTTPS.",
            10,
        )

    labels = host.split(".")
    registered_domain = ".".join(labels[-2:]) if len(labels) >= 2 else host

    for brand in BRANDS:
        if brand in host:
            exact_or_subdomain = (
                host == brand + ".com"
                or host.endswith("." + brand + ".com")
            )

            if not exact_or_subdomain and brand not in registered_domain:
                add_finding(
                    f"Possible {brand} brand impersonation in domain.",
                    "high",
                    f"Hostname {host} contains {brand!r} but is not that brand's domain or subdomain.",
                    40,
                )
                break

    if any(word in host for word in SUSPICIOUS_WORDS):
        matched_words = sorted(word for word in SUSPICIOUS_WORDS if word in host)
        add_finding(
            "Domain contains a sensitive login-related keyword.",
            "low",
            f"Hostname contains: {', '.join(matched_words)}.",
            10,
        )

    return {
        "risk_score": min(score, 100),
        "reasons": reasons,
        "findings": findings,
    }
