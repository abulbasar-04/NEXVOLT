def analyze_certificate(url: str) -> dict:
    """
    Certificate inspection is not configured yet.
    """
    return {
        "status": "unavailable",
        "valid": None,
        "days_remaining": None,
        "message": "Live SSL certificate inspection is not configured."
    }
