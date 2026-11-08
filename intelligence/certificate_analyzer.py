import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import ipaddress


def analyze_certificate(url: str) -> dict:
    """
    Validate HTTPS certificate, hostname and expiry.
    Only public IP addresses are allowed.
    """

    result = {
        "url": url,
        "status": "unknown",
        "valid": False,
        "hostname": None,
        "issuer": None,
        "subject": None,
        "expires_at": None,
        "days_remaining": None,
        "hostname_match": False,
        "error": None,
    }

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() != "https":
            result["status"] = "not_https"
            result["error"] = "Website does not use HTTPS."
            return result

        hostname = parsed.hostname

        if not hostname:
            result["status"] = "invalid_url"
            result["error"] = "Invalid hostname."
            return result

        port = parsed.port or 443
        result["hostname"] = hostname

        # Resolve hostname and reject private/internal addresses
        addresses = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )

        public_addresses = []

        for address_info in addresses:
            ip = ipaddress.ip_address(address_info[4][0])

            if not ip.is_global:
                result["status"] = "blocked"
                result["error"] = (
                    "Private or non-public IP address is not allowed."
                )
                return result

            public_addresses.append(address_info[4][0])

        if not public_addresses:
            result["status"] = "unavailable"
            result["error"] = "No public IP address found."
            return result

        # Standard certificate validation
        context = ssl.create_default_context()

        certificate = None

        for ip_address in public_addresses:
            try:
                with socket.create_connection(
                    (ip_address, port),
                    timeout=5,
                ) as raw_socket:

                    with context.wrap_socket(
                        raw_socket,
                        server_hostname=hostname,
                    ) as secure_socket:

                        certificate = secure_socket.getpeercert()
                        break

            except (OSError, ssl.SSLError):
                continue

        if not certificate:
            result["status"] = "invalid"
            result["error"] = (
                "TLS connection or certificate validation failed."
            )
            return result

        # Extract certificate details
        issuer = dict(
            item
            for group in certificate.get("issuer", [])
            for item in group
        )

        subject = dict(
            item
            for group in certificate.get("subject", [])
            for item in group
        )

        expires_at = certificate.get("notAfter")

        expiry_date = datetime.strptime(
            expires_at,
            "%b %d %H:%M:%S %Y %Z",
        ).replace(tzinfo=timezone.utc)

        days_remaining = (
            expiry_date - datetime.now(timezone.utc)
        ).days

        result.update({
            "status": "valid",
            "valid": True,
            "issuer": issuer,
            "subject": subject,
            "expires_at": expiry_date,
            "days_remaining": days_remaining,
            "hostname_match": True,
            "error": None,
        })

        if days_remaining <= 0:
            result["status"] = "expired"
            result["valid"] = False

        return result

    except ssl.SSLCertVerificationError:
        result["status"] = "invalid"
        result["error"] = "Certificate verification failed."
        return result

    except socket.gaierror:
        result["status"] = "unavailable"
        result["error"] = "Could not resolve hostname."

    except socket.timeout:
        result["status"] = "unavailable"
        result["error"] = "TLS connection timed out."

    except (ValueError, OSError, ssl.SSLError):
        result["status"] = "unavailable"
        result["error"] = "Certificate analysis failed."

    return result
