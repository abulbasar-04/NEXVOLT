from security_engine.features import extract_features


def detect_phishing(url: str) -> dict:
    """Analyze a URL using rule-based phishing detection."""

    features = extract_features(url)
    score = 0
    reasons = []

    checks = [
        ("url_length", lambda x: x > 100, 10,
         "Unusually long URL"),
        ("hostname_length", lambda x: x > 50, 10,
         "Unusually long domain name"),
        ("at_symbol_count", lambda x: x > 0, 20,
         "URL contains an @ symbol"),
        ("ip_address_used", lambda x: x == 1, 25,
         "URL uses an IP address instead of a domain"),
        ("suspicious_word_count", lambda x: x >= 2, 15,
         "Multiple suspicious keywords found"),
        ("url_shortener_used", lambda x: x == 1, 15,
         "URL uses a known shortening service"),
        ("punycode_used", lambda x: x == 1, 20,
         "Domain contains punycode"),
        ("unusual_port_used", lambda x: x == 1, 10,
         "URL uses an unusual port"),
        ("double_slash_in_path", lambda x: x == 1, 10,
         "URL contains double slashes in its path"),
        ("subdomain_count", lambda x: x >= 3, 10,
         "URL contains many subdomains"),
        ("https_used", lambda x: x == 0, 10,
         "URL does not use HTTPS"),
    ]

    for feature, condition, points, reason in checks:
        if condition(features[feature]):
            score += points
            reasons.append(reason)

    score = min(score, 100)

    if score >= 60:
        status = "High Risk"
    elif score >= 30:
        status = "Suspicious"
    else:
        status = "Safe"

    if not reasons:
        reasons.append("No suspicious URL patterns detected")

    return {
        "url": url,
        "risk_score": score,
        "status": status,
        "reasons": reasons,
        "features": features
    }
