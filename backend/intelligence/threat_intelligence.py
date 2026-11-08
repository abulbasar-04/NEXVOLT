import os
from pathlib import Path

import httpx
from dotenv import load_dotenv


# Load API configuration from backend/.env
BACKEND_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_DIR / ".env")

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")


def check_urlhaus(url: str) -> dict:
    """Check a URL against the URLhaus malware database."""

    if not isinstance(url, str) or not url.strip():
        return {
            "source": "URLhaus",
            "status": "invalid_input",
            "malicious": False,
            "details": None,
            "error": "A valid URL is required.",
        }

    if not URLHAUS_AUTH_KEY:
        return {
            "source": "URLhaus",
            "status": "unavailable",
            "malicious": False,
            "details": None,
            "error": "URLhaus API key is not configured.",
        }

    try:
        response = httpx.post(
            URLHAUS_API,
            data={"url": url.strip()},
            headers={"Auth-Key": URLHAUS_AUTH_KEY},
            timeout=10.0,
        )

        response.raise_for_status()
        data = response.json()

        query_status = data.get("query_status")

        if query_status == "ok":
            return {
                "source": "URLhaus",
                "status": "malicious",
                "malicious": True,
                "details": {
                    "url": data.get("url"),
                    "url_status": data.get("url_status"),
                    "threat": data.get("threat"),
                    "date_added": data.get("date_added"),
                    "tags": data.get("tags") or [],
                    "reporter": data.get("reporter"),
                },
                "error": None,
            }

        if query_status == "no_results":
            return {
                "source": "URLhaus",
                "status": "not_found",
                "malicious": False,
                "details": None,
                "error": None,
            }

        return {
            "source": "URLhaus",
            "status": "unknown",
            "malicious": False,
            "details": None,
            "error": "Unexpected URLhaus response.",
        }

    except httpx.TimeoutException:
        error = "URLhaus request timed out."

    except httpx.HTTPStatusError as exc:
        error = f"URLhaus HTTP error: {exc.response.status_code}"

    except httpx.RequestError:
        error = "Could not connect to URLhaus."

    except (ValueError, TypeError):
        error = "Invalid response received from URLhaus."

    return {
        "source": "URLhaus",
        "status": "unavailable",
        "malicious": False,
        "details": None,
        "error": error,
    }


def check_threat_intelligence(url: str) -> dict:
    """Main threat intelligence entry point."""

    return {
        "urlhaus": check_urlhaus(url)
    }
