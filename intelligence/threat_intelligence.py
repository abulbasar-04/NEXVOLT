import os
import requests
from urllib.parse import urlparse

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")


def validate_url(url: str) -> bool:
    parsed = urlparse(url)

    return (
        parsed.scheme in ("http", "https")
        and bool(parsed.hostname)
        and "." in parsed.hostname
    )


def check_urlhaus(url: str) -> dict:
    if not validate_url(url):
        return {
            "source": "URLhaus",
            "found": False,
            "status": "invalid_input",
            "error": "Please enter a valid HTTP or HTTPS URL."
        }

    if not URLHAUS_AUTH_KEY:
        return {
            "source": "URLhaus",
            "found": False,
            "status": "configuration_error",
            "error": "URLHAUS_AUTH_KEY is not configured."
        }


    try:
        response = requests.post(
            URLHAUS_API,
            data={"url": url},
            headers={"Auth-Key": URLHAUS_AUTH_KEY},
            timeout=15
        )

        response.raise_for_status()
        data = response.json()

    except requests.RequestException as e:
        return {
            "source": "URLhaus",
            "found": False,
            "status": "api_error",
            "error": str(e)
        }

    except ValueError:
        return {
            "source": "URLhaus",
            "found": False,
            "status": "invalid_response",
            "error": "URLhaus returned invalid JSON."
        }


    query_status = data.get("query_status")

    if query_status == "ok":
        return {
            "source": "URLhaus",
            "found": True,
            "status": "malicious",
            "url": data.get("url"),
            "threat": data.get("threat"),
            "url_status": data.get("url_status"),
            "date_added": data.get("date_added"),
            "tags": data.get("tags", []),
            "host": data.get("host"),
            "reference": data.get("urlhaus_reference")
        }

    elif query_status == "no_results":
        return {
            "source": "URLhaus",
            "found": False,
            "status": "not_listed",
            "message": "URL was not found in URLhaus."
        }

    return {
        "source": "URLhaus",
        "found": False,
        "status": "unknown",
        "message": f"Unexpected API status: {query_status}"
    }


def analyze_threat_intelligence(url: str) -> dict:
    return check_urlhaus(url)
