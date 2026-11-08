import ipaddress
import socket
import ssl

from datetime import datetime, timezone
from urllib.parse import urlparse


def analyze_certificate(url: str) -> dict:
    """Validate HTTPS certificate using a verified TLS connection."""

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
        if not isinstance(url, str) or not url.strip():
            result.update({
                "status": "invalid_url",
                "error": "A valid URL is required.",
            })
            return result

        parsed = urlparse(url.strip())

        if parsed.scheme.lower() != "https":
            result.update({
                "status": "not_https",
                "error": "Website does not use HTTPS.",
            })
            return result

        hostname = parsed.hostname

        if not hostname or parsed.username or parsed.password:
            result.update({
                "status": "invalid_url",
                "error": "Invalid hostname or URL credentials.",
            })
            return result

        port = parsed.port or 443
        result["hostname"] = hostname

        # Resolve hostname before connecting.
        addresses = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )

        public_addresses = []

        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])

            # Reject the entire destination if any resolved IP
            # is private, loopback, reserved or otherwise non-public.
            if not ip.is_global:
                result.update({
                    "status": "blocked",
                    "error": "Private or non-public IP address is blocked.",
                })
                return result

            if item[4][0] not in public_addresses:
                public_addresses.append(item[4][0])

        if not public_addresses:
            result.update({
                "status": "unavailable",
                "error": "No public IP address found.",
            })
            return result

        # Standard certificate and hostname verification.
        context = ssl.create_default_context()
        certificate = None

        # Connect directly to the resolved IP to reduce DNS
        # rebinding risk. TLS hostname verification remains enabled.
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
            result.update({
                "status": "invalid",
                "error": "TLS connection or certificate validation failed.",
            })
            return result

        issuer = {
            key: value
            for group in certificate.get("issuer", [])
            for key, value in group
        }

        subject = {
            key: value
            for group in certificate.get("subject", [])
            for key, value in group
        }

        expires_at = certificate.get("notAfter")

        if not expires_at:
            result.update({
                "status": "invalid",
                "error": "Certificate expiry date is unavailable.",
            })
            return result

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
            "expires_at": expiry_date.isoformat(),
            "days_remaining": days_remaining,
            "hostname_match": True,
            "error": None,
        })

        if days_remaining <= 0:
            result.update({
                "status": "expired",
                "valid": False,
            })

        return result

    except ssl.SSLCertVerificationError:
        result.update({
            "status": "invalid",
            "error": "Certificate or hostname verification failed.",
        })

    except socket.gaierror:
        result.update({
            "status": "unavailable",
            "error": "Could not resolve hostname.",
        })

    except socket.timeout:
        result.update({
            "status": "unavailable",
            "error": "TLS connection timed out.",
        })

    except (ValueError, OSError, ssl.SSLError, OverflowError):
        result.update({
            "status": "unavailable",
            "error": "Certificate analysis failed.",
        })

    return result
