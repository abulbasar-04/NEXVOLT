def calculate_final_risk(
    ml_result: dict,
    phishing_result: dict,
    threat_result: dict,
    certificate_result: dict,
    website_result: dict,
) -> dict:

    findings = []

    ml_probability = float(
        ml_result.get("phishing_probability", 0)
    )

    rule_score = float(
        phishing_result.get("risk_score", 0)
    )

    urlhaus = threat_result.get("urlhaus", {})
    threat_score = 100 if urlhaus.get("malicious") else 0

    score = (
        ml_probability * 0.40
        + rule_score * 0.30
        + threat_score * 0.30
    )

    if urlhaus.get("malicious"):
        score = 100
        findings.append("URLhaus confirms this URL is malicious.")

    findings.extend(phishing_result.get("reasons", []))

    # Strong brand impersonation warning
    brand_impersonation = any(
        "brand impersonation" in reason.lower()
        for reason in phishing_result.get("reasons", [])
    )

    if brand_impersonation:
        score = max(score, 75)
        findings.append(
            "High-risk brand impersonation detected."
        )

    # Certificate findings
    cert_status = certificate_result.get("status")

    if cert_status == "expired":
        score += 15
        findings.append("SSL certificate has expired.")

    elif cert_status == "invalid":
        score += 15
        findings.append("SSL certificate validation failed.")

    elif cert_status in ("unavailable", "not_https"):
        findings.append(
            "Live certificate verification is unavailable or not applicable."
        )

    days_remaining = certificate_result.get("days_remaining")

    if days_remaining is not None and 0 < days_remaining <= 30:
        score += 5
        findings.append("SSL certificate is expiring soon.")

    website_findings = website_result.get("findings", [])

    if website_findings:
        score += min(len(website_findings) * 2, 10)
        findings.extend(website_findings)

    score = round(min(max(score, 0), 100), 2)

    if urlhaus.get("malicious"):
        verdict = "Malicious"
    elif score >= 70:
        verdict = "Dangerous"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Low Risk"

    return {
        "risk_score": score,
        "verdict": verdict,
        "findings": list(dict.fromkeys(findings)),
        "score_breakdown": {
            "ml_probability": ml_probability,
            "rule_based_score": rule_score,
            "threat_intelligence_score": threat_score,
        },
    }
