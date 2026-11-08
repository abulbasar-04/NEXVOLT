
import re
import ipaddress
from urllib.parse import urlparse


def extract_url_features(url: str) -> dict:
    """
    Extract numerical URL features for NEXVOLT ML model.
    Normalize www prefix consistently across all URL features.
    """

    url = url.strip()

    # Normalize www prefix in the URL itself
    normalized_url = re.sub(
        r"(?i)(https?://)www\.",
        r"\1",
        url,
        count=1
    )

    # Parse normalized URL
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    host = hostname.lower()

    url_length = len(normalized_url)
    domain_length = len(host)

    try:
        ipaddress.ip_address(host)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    domain_parts = host.split(".")

    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    tld_length = len(tld)

    subdomain_count = max(len(domain_parts) - 2, 0)

    obfuscated_chars = len(
        re.findall(r"%[0-9a-fA-F]{2}", normalized_url)
    )

    has_obfuscation = 1 if obfuscated_chars > 0 else 0

    obfuscation_ratio = (
        obfuscated_chars / url_length if url_length > 0 else 0
    )

    letters = sum(char.isalpha() for char in normalized_url)

    letter_ratio = (
        letters / url_length if url_length > 0 else 0
    )

    digits = sum(char.isdigit() for char in normalized_url)

    digit_ratio = (
        digits / url_length if url_length > 0 else 0
    )

    equals_count = normalized_url.count("=")
    question_count = normalized_url.count("?")
    ampersand_count = normalized_url.count("&")

    other_special_chars = sum(
        not char.isalnum() and char not in "://.?&=#"
        for char in normalized_url
    )

    special_char_ratio = (
        sum(not char.isalnum() for char in normalized_url)
        / url_length
        if url_length > 0 else 0
    )

    is_https = 1 if parsed.scheme.lower() == "https" else 0

    features = {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLDLength": tld_length,
        "NoOfSubDomain": subdomain_count,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": obfuscated_chars,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": equals_count,
        "NoOfQMarkInURL": question_count,
        "NoOfAmpersandInURL": ampersand_count,
        "NoOfOtherSpecialCharsInURL": other_special_chars,
        "SpacialCharRatioInURL": special_char_ratio,
        "IsHTTPS": is_https
    }

    return features
