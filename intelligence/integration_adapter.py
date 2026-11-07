
from intelligence import (
    analyze_certificate,
    analyze_threat_intelligence
)


def analyze_security(url: str) -> dict:
    """
    Run certificate analysis and URL threat intelligence
    for the same website.
    """

    certificate_result = analyze_certificate(url)
    threat_result = analyze_threat_intelligence(url)

    return {
        "url": url,
        "certificate_analysis": certificate_result,
        "threat_intelligence": threat_result
    }


if __name__ == "__main__":
    website = input("Enter website URL: ").strip()

    result = analyze_security(website)

    print("\n===== NEXVOLT SECURITY ANALYSIS =====")
    print("URL:", result["url"])

    print("\n--- Certificate Analysis ---")
    for key, value in result["certificate_analysis"].items():
        print(f"{key}: {value}")

    print("\n--- Threat Intelligence ---")
    for key, value in result["threat_intelligence"].items():
        print(f"{key}: {value}")
