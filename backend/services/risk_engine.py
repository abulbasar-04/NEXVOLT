import math
from typing import Optional


COMPONENT_WEIGHTS = {
    "ml_probability": 0.35,
    "rule_based_score": 0.25,
    "threat_intelligence_score": 0.20,
    "certificate_risk_score": 0.10,
    "website_security_risk_score": 0.10,
}

RISK_CATEGORY_THRESHOLDS = {
    "low": 35,
    "medium": 65,
    "high": 85,
}


def _number_or_none(value) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _bounded_score(value) -> Optional[float]:
    score = _number_or_none(value)
    if score is None or not 0 <= score <= 100:
        return None
    return score


def _recommendation(source: str, code: Optional[str], title: str) -> str:
    recommendations = {
        "urlhaus_malicious": (
            "Do not visit this URL or submit information. Verify the destination "
            "through a trusted channel and follow your incident-response process."
        ),
        "community_reports_unverified": (
            "Treat community reports as unverified signals. Review the submitted "
            "evidence and corroborate it with independent sources before blocking."
        ),
        "community_reports_reviewed": (
            "Review the community evidence and corroborate it with independent "
            "sources; moderation is not proof that the URL is malicious."
        ),
        "threat_detected": (
            "Do not visit this URL or submit sensitive information. Verify the "
            "destination through a trusted channel and follow your incident-response process."
        ),
        "tls_expired": (
            "Renew and deploy the certificate, then verify the complete certificate "
            "chain before accepting sensitive connections."
        ),
        "tls_invalid": (
            "Inspect and correct the certificate chain and hostname configuration. "
            "Do not bypass browser certificate warnings."
        ),
        "tls_not_https": (
            "Serve the site over HTTPS with a correctly validated certificate; "
            "HTTP transport does not establish whether the site is legitimate."
        ),
        "tls_expiring": (
            "Renew the certificate before its expiry date and verify automated "
            "renewal is working."
        ),
        "certificate_hostname_mismatch": (
            "Deploy a certificate whose subject alternative names include the "
            "requested hostname."
        ),
        "self_signed_certificate": (
            "Install a certificate issued by a trusted CA and verify the full chain."
        ),
        "tls_invalid": (
            "Correct the certificate chain and trust configuration; do not bypass "
            "certificate warnings."
        ),
        "weak_tls_protocol": (
            "Disable obsolete SSL/TLS protocols and require TLS 1.2 or newer."
        ),
        "weak_tls_cipher": (
            "Disable weak cipher suites and prefer modern authenticated encryption."
        ),
        "weak_certificate_key": (
            "Replace the certificate with one using a modern public key of adequate size."
        ),
        "weak_certificate_signature": (
            "Reissue the certificate using a modern signature algorithm such as SHA-256 or stronger."
        ),
        "https_redirect_downgrade": (
            "Remove redirects from HTTPS to HTTP and keep the full redirect path "
            "on HTTPS."
        ),
        "cross_origin_redirect": (
            "Verify that the destination origin is expected and controlled by "
            "the site operator."
        ),
        "redirect_limit_reached": (
            "Review the redirect chain and remove unnecessary or looping redirects."
        ),
        "redirect_loop_detected": (
            "Correct the redirect configuration so the destination resolves without revisiting a prior URL."
        ),
        "suspicious_redirect_destination": (
            "Verify the redirect destination and its business purpose through a trusted channel."
        ),
        "redirect_target_blocked": (
            "Review the redirect target from a trusted environment; the scanner did not connect to it."
        ),
        "mixed_content_detected": (
            "Serve active and passive page resources over HTTPS; inspect the listed origins."
        ),
        "insecure_form_action": (
            "Submit forms only to HTTPS endpoints controlled by the site operator."
        ),
        "https_not_enforced": (
            "Redirect HTTP requests to HTTPS and verify the redirect remains on "
            "the intended site."
        ),
        "cookie_missing_secure": (
            "Set the Secure attribute on cookies that should only be sent over HTTPS."
        ),
        "cookie_samesite_none_without_secure": (
            "Add Secure to cookies using SameSite=None, and confirm cross-site "
            "cookie behavior is necessary."
        ),
        "cookie_missing_httponly": (
            "Set HttpOnly on cookies that do not need to be read by client-side code."
        ),
        "cookie_missing_samesite": (
            "Set an appropriate SameSite policy for the cookie's intended use."
        ),
        "server_header_exposed": (
            "Remove or minimize unnecessary server-version details in response headers."
        ),
        "powered_by_header_exposed": (
            "Remove the X-Powered-By response header if it is not required."
        ),
        "missing_strict_transport_security": (
            "After confirming HTTPS works across the site, configure an appropriate "
            "Strict-Transport-Security policy."
        ),
        "missing_content_security_policy": (
            "Define and test a Content-Security-Policy suited to the site's resources."
        ),
        "missing_x_content_type_options": (
            "Set X-Content-Type-Options to nosniff."
        ),
        "missing_x_frame_options": (
            "Set an appropriate frame-ancestors CSP directive or X-Frame-Options policy."
        ),
        "missing_referrer_policy": (
            "Set a Referrer-Policy appropriate to the site's privacy requirements."
        ),
        "missing_permissions_policy": (
            "Restrict browser features with a Permissions-Policy appropriate to the site."
        ),
    }

    if source == "URLhaus":
        return recommendations["urlhaus_malicious"]
    if source in ("PhishTank", "OpenPhish", "Threat intelligence"):
        return recommendations["threat_detected"]
    if isinstance(code, str) and code in recommendations:
        return recommendations[code]
    if source == "certificate_analysis":
        if code == "tls_expired":
            return recommendations["tls_expired"]
        if code == "tls_not_https":
            return recommendations["tls_not_https"]
        if code == "tls_expiring":
            return recommendations["tls_expiring"]
        return recommendations["tls_invalid"]
    if source == "rule_based":
        return (
            "Verify the exact domain through a trusted channel before opening the "
            "URL or entering credentials."
        )
    if title:
        return "Review the finding and address the evidenced condition using the site's security controls."
    return "Review the source analysis and investigate any available evidence."


def _finding(
    title: str,
    severity: str,
    evidence: str,
    source: str,
    code: Optional[str] = None,
) -> dict:
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "source": source,
        "recommendation": _recommendation(source, code, title),
    }


def _component_status(score: Optional[float], source_status: Optional[str]) -> str:
    return source_status or ("measured" if score is not None else "unavailable")


def _risk_category(risk_score: Optional[float]) -> str:
    if risk_score is None:
        return "Unknown"
    if risk_score >= RISK_CATEGORY_THRESHOLDS["high"]:
        return "Critical"
    if risk_score >= RISK_CATEGORY_THRESHOLDS["medium"]:
        return "High"
    if risk_score >= RISK_CATEGORY_THRESHOLDS["low"]:
        return "Medium"
    return "Low"


def _normalize_finding(finding: dict, default_source: str) -> Optional[dict]:
    title = finding.get("title")
    if not title:
        return None
    normalized = dict(finding)
    normalized["title"] = str(title)
    normalized.setdefault("source", default_source)
    normalized.setdefault("severity", "unknown")
    normalized.setdefault("evidence", None)
    if not normalized.get("recommendation"):
        normalized["recommendation"] = _recommendation(
            normalized["source"],
            normalized.get("code"),
            normalized["title"],
        )
    return normalized


def calculate_final_risk(
    ml_result: dict,
    phishing_result: dict,
    threat_result: dict,
    certificate_result: dict,
    website_result: dict,
) -> dict:
    ml_result = ml_result if isinstance(ml_result, dict) else {}
    phishing_result = phishing_result if isinstance(phishing_result, dict) else {}
    threat_result = threat_result if isinstance(threat_result, dict) else {}
    certificate_result = certificate_result if isinstance(certificate_result, dict) else {}
    website_result = website_result if isinstance(website_result, dict) else {}

    urlhaus = threat_result.get("urlhaus")
    urlhaus = urlhaus if isinstance(urlhaus, dict) else {}
    threat_status = str(urlhaus.get("status") or "unavailable").lower()
    aggregate_status = str(threat_result.get("status") or "").lower()
    threat_sources = threat_result.get("sources")
    threat_sources = threat_sources if isinstance(threat_sources, dict) else {}
    source_confirmed = any(
        isinstance(source, dict)
        and source_key != "community"
        and (
            source.get("malicious") is True
            or str(source.get("status") or "").lower() == "malicious"
        )
        for source_key, source in threat_sources.items()
    )
    has_external_source = any(
        source_key != "community" for source_key in threat_sources
    )
    aggregate_confirmed = (
        threat_result.get("confirmed_malicious") is True
        and (not threat_sources or has_external_source)
    )
    threat_confirmed = (
        aggregate_confirmed
        or source_confirmed
        or urlhaus.get("malicious") is True
        or threat_status == "malicious"
    )
    threat_score = (
        100.0
        if threat_confirmed
        else 0.0
        if aggregate_status == "not_found"
        or (not aggregate_status and threat_status == "not_found")
        else None
    )
    community_result = threat_sources.get("community")
    community_result = (
        community_result if isinstance(community_result, dict) else {}
    )
    community_details = community_result.get("details")
    community_details = (
        community_details if isinstance(community_details, dict) else {}
    )
    try:
        community_reporters = max(
            0, int(community_details.get("distinct_reporters") or 0)
        )
        reviewed_reporters = min(
            community_reporters,
            max(0, int(community_details.get("reviewed_reporters") or 0)),
        )
    except (TypeError, ValueError, OverflowError):
        community_reporters = 0
        reviewed_reporters = 0

    community_score = None
    if community_result.get("status") == "not_found":
        community_score = 0.0
    elif (
        community_result.get("status") in ("unverified", "reviewed")
        and community_reporters >= 2
    ):
        community_score = min(
            45.0,
            15.0
            + 10.0 * (community_reporters - 2)
            + 5.0 * min(reviewed_reporters, 2),
        )
    if community_score is not None:
        threat_score = max(threat_score or 0.0, community_score)
    threat_score_status = (
        "malicious"
        if threat_confirmed
        else community_result.get("status")
        if community_reporters
        else aggregate_status or threat_status
    )

    certificate_status = str(
        certificate_result.get("status") or "unavailable"
    ).lower()
    certificate_verification = certificate_result.get("verification")
    certificate_verification = (
        certificate_verification
        if isinstance(certificate_verification, dict)
        else {}
    )
    certificate_checks_verified = all(
        certificate_verification.get(check) == "verified"
        for check in ("validity_dates", "hostname", "chain")
    )
    certificate_findings = [
        item
        for item in certificate_result.get("finding_details") or []
        if isinstance(item, dict)
    ]
    if certificate_status in ("expired", "invalid"):
        certificate_score = 100.0
    elif certificate_status == "not_https":
        certificate_score = 50.0
    elif (
        certificate_status == "valid"
        and certificate_result.get("valid") is True
        and certificate_checks_verified
    ):
        severity_risk = {
            "critical": 100.0,
            "high": 75.0,
            "medium": 40.0,
            "low": 15.0,
            "info": 0.0,
        }
        certificate_score = max(
            [0.0] + [
                severity_risk.get(str(item.get("severity", "")).lower(), 0.0)
                for item in certificate_findings
            ]
        )
    else:
        certificate_score = None
        if certificate_status == "valid":
            certificate_status = "unverified"

    website_status = str(website_result.get("status") or "unavailable").lower()
    reported_website_score = _bounded_score(website_result.get("risk_score"))
    has_observed_website_findings = bool(website_result.get("finding_details"))
    website_score = (
        reported_website_score
        if website_status == "completed" or has_observed_website_findings
        else None
    )

    ml_probability = _bounded_score(ml_result.get("phishing_probability"))
    model_source = ml_result.get("model_source")
    if not model_source:
        ml_probability = None

    components = {
        "ml_probability": ml_probability,
        "rule_based_score": _bounded_score(phishing_result.get("risk_score")),
        "threat_intelligence_score": threat_score,
        "certificate_risk_score": certificate_score,
        "website_security_risk_score": website_score,
    }
    statuses = {
        "ml_probability": _component_status(
            components["ml_probability"],
            (
                "measured"
                if components["ml_probability"] is not None
                else ml_result.get("status")
                or (
                    "unverified_source"
                    if _bounded_score(ml_result.get("phishing_probability")) is not None
                    else None
                )
            ),
        ),
        "rule_based_score": _component_status(
            components["rule_based_score"],
            "measured" if phishing_result else None,
        ),
        "threat_intelligence_score": threat_score_status,
        "certificate_risk_score": certificate_status,
        "website_security_risk_score": website_status,
    }
    labels = {
        "ml_probability": "Trained-model phishing probability",
        "rule_based_score": "Rule-based URL heuristic score",
        "threat_intelligence_score": "Threat intelligence score",
        "certificate_risk_score": "TLS certificate risk",
        "website_security_risk_score": "Website security assessment risk",
    }

    available_weight = sum(
        COMPONENT_WEIGHTS[key]
        for key, value in components.items()
        if value is not None
    )
    weighted_risk = (
        sum(
            value * COMPONENT_WEIGHTS[key]
            for key, value in components.items()
            if value is not None
        )
        / available_weight
        if available_weight
        else None
    )

    if threat_confirmed:
        weighted_risk = 100.0

    risk_score = (
        round(min(max(weighted_risk, 0), 100), 2)
        if weighted_risk is not None
        else None
    )
    trust_score = round(100 - risk_score, 2) if risk_score is not None else None
    risk_category = _risk_category(risk_score)
    component_explanation = [
        {
            "key": key,
            "label": labels[key],
            "risk_score": components[key],
            "configured_weight": COMPONENT_WEIGHTS[key],
            "effective_weight": (
                round(COMPONENT_WEIGHTS[key] / available_weight, 4)
                if components[key] is not None and available_weight
                else 0
            ),
            "status": statuses[key],
        }
        for key in COMPONENT_WEIGHTS
    ]

    finding_details = []
    for finding in phishing_result.get("findings") or []:
        if isinstance(finding, dict):
            normalized = _normalize_finding(finding, "rule_based")
            if normalized:
                finding_details.append(normalized)

    aggregated_threat_findings = threat_result.get("findings")
    if isinstance(aggregated_threat_findings, list):
        for finding in aggregated_threat_findings:
            if not isinstance(finding, dict):
                continue
            normalized = _normalize_finding(finding, "Threat intelligence")
            if normalized:
                sources = finding.get("sources")
                if isinstance(sources, list) and sources:
                    normalized["source"] = ", ".join(str(source) for source in sources)
                finding_details.append(normalized)
    elif threat_confirmed:
        details = urlhaus.get("details")
        details = details if isinstance(details, dict) else {}
        threat_evidence = "URLhaus returned a positive match."
        if details.get("threat"):
            threat_evidence += f" Threat type: {details['threat']}."
        if details.get("date_added"):
            threat_evidence += f" Reported on: {details['date_added']}."
        finding_details.append(_finding(
            "URLhaus confirms this URL is malicious.",
            "critical",
            threat_evidence,
            "URLhaus",
            "urlhaus_malicious",
        ))

    if community_reporters:
        category_counts = community_details.get("categories")
        category_summary = (
            ", ".join(
                f"{category} ({count})"
                for category, count in sorted(category_counts.items())
            )
            if isinstance(category_counts, dict) and category_counts
            else "category not provided"
        )
        report_word = "report" if community_reporters == 1 else "reports"
        reviewed_wording = (
            "Some community reports were reviewed by a moderator, which does not "
            "establish that the URL is malicious."
            if reviewed_reporters
            else "These reports have not been verified by a moderator."
        )
        finding_code = (
            "community_reports_reviewed"
            if reviewed_reporters
            else "community_reports_unverified"
        )
        finding_details.append(_finding(
            "Community reports require independent review.",
            "medium" if community_reporters >= 2 else "low",
            (
                f"{community_reporters} distinct reporter(s) submitted reports "
                f"({category_summary}). {reviewed_wording}"
            ),
            "Community reports",
            finding_code,
        ))

    for finding in certificate_findings:
        normalized = _normalize_finding(finding, "certificate_analysis")
        if normalized:
            finding_details.append(normalized)

    existing_certificate_codes = {
        finding.get("code") for finding in certificate_findings
    }
    if certificate_status == "expired" and "tls_expired" not in existing_certificate_codes:
        finding_details.append(_finding(
            "TLS certificate has expired.",
            "high",
            certificate_result.get("error") or "Verified certificate status is expired.",
            "certificate_analysis",
            "tls_expired",
        ))
    elif certificate_status == "invalid" and not existing_certificate_codes:
        finding_details.append(_finding(
            "TLS certificate validation failed.",
            "high",
            certificate_result.get("error") or "TLS certificate verification failed.",
            "certificate_analysis",
            "tls_invalid",
        ))
    elif certificate_status == "not_https":
        finding_details.append(_finding(
            "The URL does not use HTTPS.",
            "medium",
            certificate_result.get("error") or "The analyzed URL uses HTTP rather than HTTPS.",
            "certificate_analysis",
            "tls_not_https",
        ))

    days_remaining = _number_or_none(certificate_result.get("days_remaining"))
    if (
        certificate_status == "valid"
        and days_remaining is not None
        and 0 < days_remaining <= 30
        and "tls_expiring" not in existing_certificate_codes
    ):
        finding_details.append(_finding(
            "TLS certificate is expiring soon.",
            "medium",
            f"Certificate expires in {int(days_remaining)} day(s).",
            "certificate_analysis",
            "tls_expiring",
        ))

    for finding in website_result.get("finding_details") or []:
        if isinstance(finding, dict):
            normalized = _normalize_finding(finding, "website_assessment")
            if normalized:
                finding_details.append(normalized)

    unique_findings = []
    seen = set()
    for finding in finding_details:
        key = (finding.get("title"), finding.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)

    findings = list(dict.fromkeys(
        finding["title"]
        for finding in unique_findings
        if finding.get("title")
    ))

    if risk_score is None:
        verdict = "Unknown"
    elif threat_confirmed:
        verdict = "Malicious"
    elif risk_score >= 70:
        verdict = "Dangerous"
    elif risk_score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Low Risk"

    return {
        "risk_score": risk_score,
        "trust_score": trust_score,
        "risk_category": risk_category,
        "verdict": verdict,
        "findings": findings,
        "finding_details": unique_findings,
        "score_breakdown": components,
        "score_explanation": {
            "method": (
                "Weighted mean of available risk components; unavailable or "
                "invalid sources are excluded and remaining weights are "
                "normalized. A confirmed URLhaus malicious match sets risk to "
                "100. A URLhaus no-match applies only to that feed and is not "
                "proof of safety. ML probability is one signal, not certainty; "
                "valid HTTPS does not establish site legitimacy. No numeric "
                "score is reported when no component is available. Community "
                "reports contribute conservatively, are capped at 45, and never "
                "independently confirm maliciousness."
            ),
            "risk_score": risk_score,
            "trust_score": trust_score,
            "risk_category": risk_category,
            "available_weight": round(available_weight, 4),
            "coverage_percent": round(available_weight * 100, 1),
            "category_thresholds": {
                "low": "0-34.99",
                "medium": "35-64.99",
                "high": "65-84.99",
                "critical": "85-100",
            },
            "components": component_explanation,
        },
    }
