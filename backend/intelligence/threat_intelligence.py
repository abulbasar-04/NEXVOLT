def check_threat_intelligence(url: str) -> dict:
    """
    No live threat-intelligence provider is configured.
    Never claim that an unchecked URL is safe.
    """
    return {
        "urlhaus": {
            "malicious": False,
            "status": "unavailable",
            "message": "Live URLhaus lookup is not configured."
        }
    }
