
import re
import ipaddress
from urllib.parse import urlparse


def extract_url_features(url: str) -> dict:
    """
    Extract numerical URL features for NEXVOLT ML model.
    """

    url = url.strip()

    # Parse URL
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    host = hostname.lower()

    # URL length
    url_length = len(url)

    # Domain length
    domain_length = len(host)

    # IP address detection
    try:
        ipaddress.ip_address(host)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    # TLD length
    domain_parts = host.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    tld_length = len(tld)

    # Subdomain count
    subdomain_count = max(len(domain_parts) - 2, 0)

    # Obfuscation detection
    obfuscated_chars = len(
        re.findall(r"%[0-9a-fA-F]{2}", url)
    )

    has_obfuscation = 1 if obfuscated_chars > 0 else 0

    obfuscation_ratio = (
        obfuscated_chars / url_length
        if url_length > 0 else 0
    )

    # Letters
    letters = sum(char.isalpha() for char in url)
    letter_ratio = letters / url_length if url_length else 0

    # Digits
    digits = sum(char.isdigit() for char in url)
    digit_ratio = digits / url_length if url_length else 0

    # Special characters
    equals_count = url.count("=")
    question_count = url.count("?")
    ampersand_count = url.count("&")

    other_special_chars = sum(
        not char.isalnum() and char not in "://.?&=#"
        for char in url
    )

    special_char_ratio = (
        sum(not char.isalnum() for char in url) / url_length
        if url_length else 0
    )

    # HTTPS
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    # Feature dictionary
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
        "IsHTTPS": is_https,
    }

    return features
