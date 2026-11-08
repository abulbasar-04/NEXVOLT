import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing",
    "content-security-policy": "CSP missing",
    "x-content-type-options": "X-Content-Type-Options missing",
    "x-frame-options": "X-Frame-Options missing",
    "referrer-policy": "Referrer-Policy missing",
}


def is_public_host(hostname: str) -> bool:
    """Reject private, loopback and non-public destinations."""

    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_global
    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        if not addresses:
            return False

        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])

            if not ip.is_global:
                return False

        return True

    except (socket.gaierror, OSError, ValueError):
        return False


def validate_url(url: str) -> bool:
    """Validate URL before making an HTTP request."""

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        if parsed.username or parsed.password:
            return False

        if parsed.port is not None:
            allowed_port = (
                parsed.scheme == "http" and parsed.port == 80
            ) or (
                parsed.scheme == "https" and parsed.port == 443
            )

            if not allowed_port:
                return False

        return is_public_host(parsed.hostname)

    except ValueError:
        return False


def scan_website(url: str) -> dict:
    """Perform basic passive HTTP security assessment."""

    result = {
        "url": url,
        "status": "unknown",
        "http_status": None,
        "final_url": None,
        "redirects": [],
        "security_headers": {},
        "missing_headers": [],
        "server": None,
        "powered_by": None,
        "findings": [],
        "error": None,
    }

    if not isinstance(url, str) or not url.strip():
        result["status"] = "invalid_url"
        result["error"] = "URL is required."
        return result

    current_url = url.strip()

    if not current_url.startswith(("http://", "https://")):
        current_url = "https://" + current_url

    if not validate_url(current_url):
        result["status"] = "blocked"
        result["error"] = (
            "URL rejected: invalid destination or non-public host."
        )
        return result

    try:
        with httpx.Client(
            timeout=8.0,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": "NEXVOLT-SecurityScanner/1.0"},
        ) as client:

            for _ in range(6):
                if not validate_url(current_url):
                    result["status"] = "blocked"
                    result["error"] = (
                        "Redirect to a non-public or invalid destination blocked."
                    )
                    return result

                response = client.get(current_url)

                location = response.headers.get("location")

                if response.status_code in (301, 302, 303, 307, 308) and location:
                    next_url = urljoin(current_url, location)

                    result["redirects"].append({
                        "from": current_url,
                        "to": next_url,
                        "status": response.status_code,
                    })

                    current_url = next_url
                    continue

                result["http_status"] = response.status_code
                result["final_url"] = str(response.url)

                headers = {
                    key.lower(): value
                    for key, value in response.headers.items()
                }

                for header in SECURITY_HEADERS:
                    present = header in headers

                    result["security_headers"][header] = present

                    if not present:
                        result["missing_headers"].append(
                            SECURITY_HEADERS[header]
                        )

                result["server"] = headers.get("server")
                result["powered_by"] = headers.get("x-powered-by")

                if current_url.startswith("http://"):
                    result["findings"].append(
                        "Website uses HTTP instead of HTTPS."
                    )

                if result["missing_headers"]:
                    result["findings"].append(
                        "Some recommended security headers are missing."
                    )

                if result["server"]:
                    result["findings"].append(
                        "Server technology information is exposed."
                    )

                if result["powered_by"]:
                    result["findings"].append(
                        "X-Powered-By information is exposed."
                    )

                result["status"] = "completed"
                result["error"] = None

                return result

            result["status"] = "redirect_limit"
            result["error"] = "Too many redirects."

    except httpx.TimeoutException:
        result["status"] = "unavailable"
        result["error"] = "Website request timed out."

    except httpx.ConnectError:
        result["status"] = "unavailable"
        result["error"] = "Could not connect to website."

    except httpx.HTTPError:
        result["status"] = "unavailable"
        result["error"] = "Website HTTP request failed."

    return result
