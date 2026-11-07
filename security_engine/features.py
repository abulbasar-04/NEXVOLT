import re
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure",
    "account", "banking", "password", "confirm",
    "signin", "wallet", "payment"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "is.gd", "cutt.ly"
]


def extract_features(url: str) -> dict:
    """Extract basic security-related features from a URL."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string.")

    url = url.strip()

    if len(url) > 2048:
        raise ValueError("URL is too long.")

    if any(ord(char) < 32 for char in url):
        raise ValueError("URL contains invalid control characters.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Invalid URL. Enter a valid HTTP or HTTPS URL.")

    hostname = parsed.hostname.lower()
    full_url = url.lower()

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = 1
    except ValueError:
        is_ip_address = 0

    try:
        port = parsed.port
    except ValueError:
        port = None

    subdomain_count = max(0, len(hostname.split(".")) - 2)

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_symbol_count": url.count("@"),
        "question_mark_count": url.count("?"),
        "equal_count": url.count("="),
        "percent_count": url.count("%"),
        "ampersand_count": url.count("&"),
        "digit_count": sum(char.isdigit() for char in url),
        "subdomain_count": subdomain_count,
        "https_used": int(parsed.scheme.lower() == "https"),
        "ip_address_used": is_ip_address,
        "suspicious_word_count": sum(
            word in full_url for word in SUSPICIOUS_WORDS
        ),
        "url_shortener_used": int(
            any(hostname == domain or hostname.endswith("." + domain)
                for domain in URL_SHORTENERS)
        ),
        "punycode_used": int("xn--" in hostname),
        "unusual_port_used": int(port is not None and port not in (80, 443)),
        "double_slash_in_path": int("//" in parsed.path),
    }

    return features
