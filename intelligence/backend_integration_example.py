from intelligence import (
    analyze_certificate,
    analyze_threat_intelligence
)


def backend_security_analysis(url: str) -> dict:
    """
    Backend Integration Example for NEXVOLT.

    Connects Certificate Analyzer and URLhaus
    Threat Intelligence with a backend-style response.
    """

    url = url.strip()

    if not url:
        return {
            "success": False,
            "url": None,
            "certificate_analysis": None,
            "threat_intelligence": None,
            "error": "URL cannot be empty"
        }

    certificate_result = None
    threat_result = None
    errors = []

    # Certificate Analysis
    try:
        certificate_result = analyze_certificate(url)
    except Exception as error:
        errors.append(f"Certificate Analysis: {error}")

    # URL Threat Intelligence
    try:
        threat_result = analyze_threat_intelligence(url)
    except Exception as error:
        errors.append(f"Threat Intelligence: {error}")

    return {
        "success": len(errors) == 0,
        "url": url,
        "certificate_analysis": certificate_result,
        "threat_intelligence": threat_result,
        "errors": errors
    }


if __name__ == "__main__":

    print("=" * 50)
    print(" NEXVOLT BACKEND INTEGRATION EXAMPLE")
    print("=" * 50)

    website_url = input("\nEnter website URL: ")

    response = backend_security_analysis(website_url)

    print("\nBACKEND RESPONSE")
    print("-" * 50)

    import json

    print(json.dumps(response, indent=4))

    print("\n" + "=" * 50)
