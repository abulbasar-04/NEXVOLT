def scan_website(url: str) -> dict:
    """
    Passive scan only.
    Does not fetch arbitrary URLs or access private network resources.
    """
    findings = []

    if not url.lower().startswith("https://"):
        findings.append("Website does not use HTTPS.")

    return {
        "findings": findings,
        "status": "passive_scan",
        "message": (
            "Passive URL checks completed. "
            "HTTP security headers were not remotely inspected."
        )
    }
