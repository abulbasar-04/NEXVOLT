import socket
import ssl
import hashlib
from datetime import datetime, timezone


def analyze_certificate(url: str) -> dict:
    """
    Analyze the SSL/TLS certificate of a website.
    Returns certificate details and validation status.
    """

    try:
        # Extract hostname
        hostname = url.replace("https://", "").replace("http://", "")
        hostname = hostname.split("/")[0].split(":")[0]

        context = ssl.create_default_context()

        # Connect using verified TLS
        with socket.create_connection(
            (hostname, 443), timeout=8
        ) as sock:

            with context.wrap_socket(
                sock, server_hostname=hostname
            ) as tls_socket:

                cert = tls_socket.getpeercert()
                binary_cert = tls_socket.getpeercert(binary_form=True)

                issuer = dict(
                    x[0] for x in cert.get("issuer", [])
                )

                subject = dict(
                    x[0] for x in cert.get("subject", [])
                )

                expiry_date = datetime.strptime(
                    cert["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)

                days_remaining = (
                    expiry_date - now
                ).days

                fingerprint = hashlib.sha256(
                    binary_cert
                ).hexdigest()

                return {
                    "hostname": hostname,
                    "valid": True,
                    "hostname_verified": True,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "subject": subject.get("commonName", "Unknown"),
                    "expiry_date": expiry_date.isoformat(),
                    "days_remaining": days_remaining,
                    "expired": days_remaining < 0,
                    "tls_version": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0],
                    "fingerprint_sha256": fingerprint
                }

    except ssl.SSLCertVerificationError as e:
        return {
            "hostname": hostname if "hostname" in locals() else url,
            "valid": False,
            "error": "Certificate verification failed",
            "details": str(e)
        }

    except Exception as e:
        return {
            "hostname": url,
            "valid": False,
            "error": "Certificate analysis failed",
            "details": str(e)
        }
