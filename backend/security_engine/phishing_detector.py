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
    score = 0

    if not host:
        return {"risk_score": 100, "reasons": ["Invalid hostname"]}

    try:
        ipaddress.ip_address(host)
        score += 35
        reasons.append("URL uses an IP address instead of a domain.")
    except ValueError:
        pass

    if "@" in url:
        score += 25
        reasons.append("URL contains an @ symbol.")

    if host.count("-") >= 2:
        score += 15
        reasons.append("Domain contains multiple hyphens.")

    if len(url) > 100:
        score += 10
        reasons.append("Unusually long URL.")

    if parsed.scheme != "https":
        score += 10
        reasons.append("URL does not use HTTPS.")

    labels = host.split(".")
    registered_domain = ".".join(labels[-2:]) if len(labels) >= 2 else host

    for brand in BRANDS:
        if brand in host:
            exact_or_subdomain = (
                host == brand + ".com"
                or host.endswith("." + brand + ".com")
            )

            if not exact_or_subdomain and brand not in registered_domain:
                score += 40
                reasons.append(
                    f"Possible {brand} brand impersonation in domain."
                )
                break

    if any(word in host for word in SUSPICIOUS_WORDS):
        score += 10
        reasons.append("Domain contains a sensitive login-related keyword.")

    return {
        "risk_score": min(score, 100),
        "reasons": reasons
    }
