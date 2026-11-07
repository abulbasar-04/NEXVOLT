
from intelligence.integration_adapter import analyze_security


def run_demo():
    print("=" * 50)
    print("          NEXVOLT SECURITY DEMO")
    print("=" * 50)

    url = input("\nEnter website URL: ").strip()

    try:
        result = analyze_security(url)

        cert = result["certificate_analysis"]
        threat = result["threat_intelligence"]

        print("\n" + "=" * 50)
        print("           SECURITY REPORT")
        print("=" * 50)

        print(f"\nTarget URL: {result['url']}")

        print("\n[1] CERTIFICATE ANALYSIS")
        print("-" * 30)
        print("Certificate Valid :", cert.get("valid"))
        print("Hostname Verified :", cert.get("hostname_verified"))
        print("TLS Version      :", cert.get("tls_version"))
        print("Issuer           :", cert.get("issuer"))
        print("Expiry Date      :", cert.get("expiry_date"))

        print("\n[2] THREAT INTELLIGENCE")
        print("-" * 30)
        print("Source            :", threat.get("source"))
        print("Threat Detected   :", threat.get("found"))
        print("Status            :", threat.get("status"))
        print("Threat Type       :", threat.get("threat"))

        print("\n" + "=" * 50)
        print("        SECURITY ANALYSIS COMPLETE")
        print("=" * 50)

    except Exception as error:
        print("\nSecurity analysis failed:", error)


if __name__ == "__main__":
    run_demo()
