import hashlib
import ipaddress
import json
import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa


logger = logging.getLogger(__name__)
CT_LOG_LOOKUP_URL = "https://crt.sh/"
CT_LOOKUP_TIMEOUT = 5.0
MAX_CT_RECORDS = 20
MAX_CT_RESPONSE_BYTES = 2_000_000
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = (
    "NULL",
    "EXPORT",
    "RC4",
    "DES-CBC",
    "3DES",
    "3DES-EDE",
    "MD5",
    "ANON",
)


def _empty_result(url: str) -> dict:
    return {
        "url": url,
        "status": "unknown",
        "valid": False,
        "hostname": None,
        "issuer": None,
        "subject": None,
        "subject_alt_names": [],
        "expires_at": None,
        "not_before": None,
        "days_remaining": None,
        "tls_version": None,
        "cipher": None,
        "sha256_fingerprint": None,
        "serial_number": None,
        "certificate_metadata_status": "unavailable",
        "hostname_match": None,
        "error": None,
        "verification": {
            "status": "unavailable",
            "validity_dates": "unavailable",
            "hostname": "unavailable",
            "chain": "unavailable",
            "self_signed": "unavailable",
        },
        "certificate_chain": {
            "status": "unsupported",
            "verification": "unavailable",
            "certificates": [],
        },
        "public_key": {"status": "unavailable"},
        "signature": {"status": "unavailable"},
        "tls_assessment": {"status": "unavailable"},
        "trust_intelligence": {
            "ca_trust": {"status": "unavailable"},
            "known_distrust": {"status": "unsupported"},
            "certificate_transparency": {"status": "unavailable"},
            "revocation": {"status": "unsupported"},
        },
        "findings": [],
        "finding_details": [],
    }


def _resolve_public_addresses(hostname: str, port: int) -> list[tuple]:
    addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise socket.gaierror(f"No addresses found for {hostname}.")

    public = []
    seen = set()
    for family, socktype, protocol, _canonical_name, sockaddr in addresses:
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global:
            raise ValueError("Private or non-public IP address is blocked.")
        if (family, socktype, protocol, sockaddr) not in seen:
            public.append((family, socktype, protocol, sockaddr))
            seen.add((family, socktype, protocol, sockaddr))
    return public


def _certificate_metadata(certificate_der: bytes) -> dict:
    certificate = x509.load_der_x509_certificate(certificate_der)
    now = datetime.now(timezone.utc)
    not_before = getattr(certificate, "not_valid_before_utc", None)
    not_after = getattr(certificate, "not_valid_after_utc", None)
    if not_before is None:
        not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    days_remaining = int((not_after - now).total_seconds() // 86400)
    sans = []
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        sans = [
            {"type": "DNS", "value": name}
            for name in extension.value.get_values_for_type(x509.DNSName)
        ]
        sans.extend(
            {
                "type": "IP Address",
                "value": str(address),
            }
            for address in extension.value.get_values_for_type(x509.IPAddress)
        )
    except x509.ExtensionNotFound:
        pass

    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type = "EC"
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_type = "DSA"
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        key_type = "Ed25519"
    elif isinstance(public_key, ed448.Ed448PublicKey):
        key_type = "Ed448"
    else:
        key_type = type(public_key).__name__

    key_size = getattr(public_key, "key_size", None)
    try:
        signature_hash = certificate.signature_hash_algorithm
        signature_algorithm = (
            signature_hash.name
            if signature_hash is not None
            else certificate.signature_algorithm_oid._name
        )
        signature_status = "verified"
    except UnsupportedAlgorithm:
        signature_algorithm = certificate.signature_algorithm_oid._name
        signature_status = "unsupported"
    subject = {
        attribute.oid._name or attribute.oid.dotted_string: attribute.value
        for attribute in certificate.subject
    }
    issuer = {
        attribute.oid._name or attribute.oid.dotted_string: attribute.value
        for attribute in certificate.issuer
    }
    return {
        "certificate": certificate,
        "issuer": issuer,
        "subject": subject,
        "subject_alt_names": sans,
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "public_key": {
            "status": "verified",
            "algorithm": key_type,
            "key_size": key_size,
            "sha256_fingerprint": hashlib.sha256(
                public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest(),
        },
        "signature": {
            "status": signature_status,
            "algorithm": signature_algorithm,
            "oid": certificate.signature_algorithm_oid.dotted_string,
        },
        "sha256_fingerprint": certificate.fingerprint(
            hashes.SHA256()
        ).hex(),
        "serial_number": format(certificate.serial_number, "x"),
    }


def _apply_metadata(
    result: dict,
    metadata: dict,
    tls_version: str,
    cipher: tuple,
) -> None:
    result.update({
        "issuer": metadata["issuer"],
        "subject": metadata["subject"],
        "subject_alt_names": metadata["subject_alt_names"],
        "not_before": metadata["not_before"].isoformat(),
        "expires_at": metadata["not_after"].isoformat(),
        "days_remaining": metadata["days_remaining"],
        "sha256_fingerprint": metadata["sha256_fingerprint"],
        "serial_number": metadata["serial_number"],
        "tls_version": tls_version,
        "cipher": {
            "name": cipher[0],
            "protocol": cipher[1],
            "bits": cipher[2],
        } if cipher else None,
        "public_key": metadata["public_key"],
        "signature": metadata["signature"],
    })


def _inspect_unverified_peer(hostname: str, port: int, addresses: list[tuple]):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    for _family, _socktype, _protocol, sockaddr in addresses:
        try:
            with socket.create_connection(sockaddr, timeout=5) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=hostname) as peer:
                    return (
                        peer.getpeercert(binary_form=True),
                        peer.version(),
                        peer.cipher(),
                    )
        except (AttributeError, TypeError, socket.timeout, OSError, ssl.SSLError):
            continue
    return None, None, None


def _key_or_signature_findings(metadata: dict) -> list[dict]:
    findings = []
    key = metadata["public_key"]
    algorithm = key.get("algorithm")
    key_size = key.get("key_size")
    weak_key = (
        (algorithm == "RSA" and key_size is not None and key_size < 2048)
        or (algorithm == "DSA" and key_size is not None and key_size < 2048)
        or (algorithm == "EC" and key_size is not None and key_size < 224)
    )
    if weak_key:
        findings.append({
            "code": "weak_certificate_key",
            "title": "Certificate uses a weak public key.",
            "severity": "high",
            "evidence": f"Public key is {algorithm} with {key_size} bits.",
            "source": "certificate_analysis",
            "recommendation": "Replace the certificate with one using a modern key of adequate size.",
        })

    signature_algorithm = str(metadata["signature"].get("algorithm") or "").lower()
    if "md5" in signature_algorithm or "sha1" in signature_algorithm:
        findings.append({
            "code": "weak_certificate_signature",
            "title": "Certificate uses a weak signature hash.",
            "severity": "high",
            "evidence": f"Certificate signature hash is {metadata['signature']['algorithm']}.",
            "source": "certificate_analysis",
            "recommendation": "Reissue the certificate using a modern signature algorithm such as SHA-256 or stronger.",
        })
    return findings


def _transparency_lookup(hostname: str) -> dict:
    result = {
        "status": "unavailable",
        "provider": "crt.sh",
        "coverage": "partial",
        "entries": [],
        "entry_count": None,
        "error": None,
    }
    try:
        response_body = bytearray()
        with httpx.stream(
            "GET",
            CT_LOG_LOOKUP_URL,
            params={"q": f"%.{hostname}", "output": "json"},
            timeout=CT_LOOKUP_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
            headers={"Accept": "application/json"},
        ) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                response_body.extend(chunk)
                if len(response_body) > MAX_CT_RESPONSE_BYTES:
                    result.update(
                        status="unknown",
                        error="CT lookup response exceeded the size limit.",
                    )
                    return result
        payload = json.loads(response_body)
        if not isinstance(payload, list):
            result.update(status="unknown", error="Unexpected CT lookup response.")
            return result
        entries = []
        seen = set()
        for item in payload:
            if not isinstance(item, dict):
                continue
            entry_id = item.get("id")
            key = entry_id or (
                item.get("issuer_name"),
                item.get("not_before"),
                item.get("not_after"),
            )
            if key in seen:
                continue
            seen.add(key)
            entries.append({
                "id": entry_id,
                "issuer": item.get("issuer_name"),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
                "matching_names": item.get("name_value"),
            })
        result.update(
            status="checked",
            entry_count=len(seen),
            entries=entries[:MAX_CT_RECORDS],
        )
    except httpx.TimeoutException:
        result.update(error="CT lookup timed out.")
    except httpx.HTTPStatusError as error:
        result.update(error=f"CT lookup returned HTTP {error.response.status_code}.")
    except httpx.RequestError:
        result.update(error="Could not connect to the CT lookup provider.")
    except (ValueError, TypeError, json.JSONDecodeError):
        result.update(status="unknown", error="Invalid CT lookup response.")
    return result


def _verification_error(error: ssl.SSLCertVerificationError) -> dict:
    verify_code = getattr(error, "verify_code", None)
    verify_message = getattr(error, "verify_message", None)
    if not verify_message:
        verify_message = str(error)
    message = str(verify_message).lower()
    details = {
        "status": "failed",
        "validity_dates": "unavailable",
        "hostname": "unavailable",
        "chain": "failed",
        "self_signed": "unsupported",
        "error": str(verify_message),
    }
    if verify_code in (10, 11) or "expired" in message:
        details["validity_dates"] = "failed"
    elif verify_code == 9 or "not yet valid" in message:
        details["validity_dates"] = "failed"
    if verify_code in (18, 19) or "self-signed" in message:
        details["self_signed"] = "detected"
    if "hostname" in message or "doesn't match" in message:
        details["hostname"] = "failed"
    return details


def _verification_finding(result: dict) -> dict:
    verification = result["verification"]
    if verification["self_signed"] == "detected":
        code = "self_signed_certificate"
        title = "A self-signed or untrusted self-issued certificate was detected."
        recommendation = "Install a certificate issued by a trusted CA and verify the full chain."
        severity = "high"
    elif verification["hostname"] == "failed":
        code = "certificate_hostname_mismatch"
        title = "Certificate hostname validation failed."
        recommendation = "Deploy a certificate whose subject alternative names include the requested hostname."
        severity = "high"
    elif result["status"] == "expired":
        code = "tls_expired"
        title = "TLS certificate has expired."
        recommendation = "Renew and deploy the certificate, then verify the complete chain."
        severity = "high"
    else:
        code = "tls_invalid"
        title = "TLS certificate or chain validation failed."
        recommendation = "Correct the certificate chain and trust configuration; do not bypass certificate warnings."
        severity = "high"
    return {
        "code": code,
        "title": title,
        "severity": severity,
        "evidence": verification.get("error") or result.get("error"),
        "source": "certificate_analysis",
        "recommendation": recommendation,
    }


def analyze_certificate(url: str, include_transparency: bool = True) -> dict:
    """Assess a public HTTPS endpoint; optionally skip the CT provider lookup."""
    result = _empty_result(url)
    try:
        if not isinstance(url, str) or not url.strip():
            result.update(status="invalid_url", error="A valid URL is required.")
            return result

        parsed = urlparse(url.strip())
        if parsed.scheme.lower() != "https":
            result.update({
                "status": "not_https",
                "valid": False,
                "hostname_match": False,
                "error": "Website does not use HTTPS.",
            })
            result["verification"].update(
                status="failed",
                hostname="not_applicable",
                validity_dates="not_applicable",
                chain="not_applicable",
                self_signed="not_applicable",
            )
            return result
        hostname = parsed.hostname
        if not hostname or parsed.username or parsed.password:
            result.update(status="invalid_url", error="Invalid hostname or URL credentials.")
            return result

        port = parsed.port or 443
        result["hostname"] = hostname
        addresses = _resolve_public_addresses(hostname, port)
        context = ssl.create_default_context()
        verification_errors = []
        connection_errors = []
        certificate_der = None
        tls_version = None
        cipher = None
        verified_chain = None

        for _family, _socktype, _protocol, sockaddr in addresses:
            try:
                with socket.create_connection(sockaddr, timeout=5) as raw_socket:
                    with context.wrap_socket(
                        raw_socket,
                        server_hostname=hostname,
                    ) as secure_socket:
                        certificate_der = secure_socket.getpeercert(binary_form=True)
                        tls_version = secure_socket.version()
                        cipher = secure_socket.cipher()
                        get_chain = getattr(secure_socket, "get_verified_chain", None)
                        if callable(get_chain):
                            verified_chain = get_chain()
                        result["verification"] = {
                            "status": "verified",
                            "validity_dates": "verified",
                            "hostname": "verified",
                            "chain": "verified",
                            "self_signed": "not_detected",
                        }
                        result["trust_intelligence"]["ca_trust"] = {
                            "status": "verified",
                            "trust_store": "system",
                            "message": "TLS chain validated by the system trust store.",
                        }
                        break
            except ssl.SSLCertVerificationError as error:
                verification_errors.append(error)
                continue
            except (socket.timeout, OSError, ssl.SSLError) as error:
                connection_errors.append(error)
                continue

        if certificate_der is None:
            if verification_errors:
                error = verification_errors[-1]
                result["verification"] = _verification_error(error)
                result["trust_intelligence"]["ca_trust"] = {
                    "status": "failed",
                    "trust_store": "system",
                    "message": "TLS verification failed against the system trust store.",
                }
                result["hostname_match"] = (
                    False
                    if result["verification"]["hostname"] == "failed"
                    else None
                )
                reason = str(getattr(error, "verify_message", error)).lower()
                verify_code = getattr(error, "verify_code", None)
                if verify_code in (10, 11) or "expired" in reason:
                    result.update(status="expired", error="The certificate is expired.")
                else:
                    result.update(
                        status="invalid",
                        error=result["verification"].get("error") or "Certificate verification failed.",
                    )
                result["certificate_chain"].update(
                    status="unsupported",
                    verification=result["verification"]["chain"],
                    message="Chain certificate details are unavailable for a failed TLS validation.",
                )
                try:
                    peer_der, peer_protocol, peer_cipher = _inspect_unverified_peer(
                        hostname,
                        port,
                        addresses,
                    )
                    if peer_der:
                        peer_metadata = _certificate_metadata(peer_der)
                        _apply_metadata(result, peer_metadata, peer_protocol, peer_cipher)
                        result["certificate_metadata_status"] = "observed_unverified"
                        result["tls_assessment"] = {
                            "status": "observed_unverified",
                            "protocol": peer_protocol,
                            "protocol_status": (
                                "weak" if peer_protocol in WEAK_PROTOCOLS else "acceptable"
                            ),
                            "cipher_status": "observed_unverified",
                            "findings": [],
                        }
                        if peer_metadata["not_after"] <= datetime.now(timezone.utc):
                            result["status"] = "expired"
                            result["verification"]["validity_dates"] = "failed"
                            result["error"] = "The certificate is expired."
                except (UnsupportedAlgorithm, ValueError, TypeError):
                    result["certificate_metadata_status"] = "unavailable"
                if result["verification"]["hostname"] == "failed":
                    result["hostname_match"] = False
                if result["verification"]["self_signed"] == "detected":
                    result["findings"].append(
                        "A self-signed or untrusted self-issued certificate was detected."
                    )
                result["finding_details"].append(_verification_finding(result))
                return result

            if any(isinstance(error, socket.timeout) for error in connection_errors):
                result.update(status="unavailable", error="TLS connection timed out.")
            else:
                result.update(status="unavailable", error="Could not establish a TLS connection.")
            return result

        try:
            metadata = _certificate_metadata(certificate_der)
        except (UnsupportedAlgorithm, ValueError, TypeError):
            result.update(
                status="invalid",
                valid=False,
                error="Certificate metadata could not be decoded or analyzed.",
            )
            result["verification"].update(status="failed", validity_dates="failed")
            result["finding_details"].append(_verification_finding(result))
            return result
        certificate = metadata.pop("certificate")
        _apply_metadata(result, metadata, tls_version, cipher)
        result["certificate_metadata_status"] = "verified"
        result["hostname_match"] = True
        now = datetime.now(timezone.utc)
        dates_valid = metadata["not_before"] <= now < metadata["not_after"]
        result["verification"]["validity_dates"] = (
            "verified" if dates_valid else "failed"
        )
        if not dates_valid:
            result["verification"]["status"] = "failed"
            result["status"] = (
                "expired" if metadata["not_after"] <= now else "invalid"
            )
            result["valid"] = False
            result["error"] = (
                "The certificate is expired."
                if result["status"] == "expired"
                else "The certificate is not yet valid."
            )
            result["finding_details"].append(_verification_finding(result))
            result["findings"].append(result["finding_details"][-1]["title"])
        else:
            result["status"] = "valid"
            result["valid"] = all(
                result["verification"][check] == "verified"
                for check in ("validity_dates", "hostname", "chain")
            )
            if not result["valid"]:
                result["status"] = "invalid"
                result["verification"]["status"] = "failed"

        if verified_chain:
            chain_certificates = []
            for chain_certificate in verified_chain:
                try:
                    if isinstance(chain_certificate, x509.Certificate):
                        der = chain_certificate.public_bytes(serialization.Encoding.DER)
                        chain_metadata = _certificate_metadata(der)
                    elif hasattr(chain_certificate, "public_bytes"):
                        pem = chain_certificate.public_bytes()
                        parsed_chain_certificate = x509.load_pem_x509_certificate(pem)
                        chain_metadata = _certificate_metadata(
                            parsed_chain_certificate.public_bytes(serialization.Encoding.DER)
                        )
                    else:
                        chain_metadata = _certificate_metadata(chain_certificate)
                    if chain_metadata:
                        chain_certificates.append({
                            "subject": chain_metadata["subject"],
                            "issuer": chain_metadata["issuer"],
                            "sha256_fingerprint": chain_metadata["sha256_fingerprint"],
                        })
                except (ValueError, TypeError):
                    continue
            result["certificate_chain"] = {
                "status": (
                    "available"
                    if len(chain_certificates) == len(verified_chain)
                    else "partial"
                    if chain_certificates
                    else "unavailable"
                ),
                "verification": "verified",
                "certificates": chain_certificates,
            }
        else:
            result["certificate_chain"] = {
                "status": "unsupported",
                "verification": "verified",
                "certificates": [],
            }

        tls_findings = []
        if tls_version in WEAK_PROTOCOLS:
            tls_findings.append({
                "code": "weak_tls_protocol",
                "title": "A deprecated TLS protocol was negotiated.",
                "severity": "high",
                "evidence": f"Negotiated protocol: {tls_version}.",
                "source": "certificate_analysis",
                "recommendation": "Disable obsolete SSL/TLS protocols and require TLS 1.2 or newer.",
            })
        weak_cipher = bool(cipher) and (
            cipher[2] < 128
            or any(marker in cipher[0].upper() for marker in WEAK_CIPHER_MARKERS)
        )
        if weak_cipher:
            tls_findings.append({
                "code": "weak_tls_cipher",
                "title": "A weak TLS cipher was negotiated.",
                "severity": "high",
                "evidence": f"Negotiated cipher: {cipher[0]} ({cipher[2]} bits).",
                "source": "certificate_analysis",
                "recommendation": "Disable weak cipher suites and prefer modern authenticated encryption.",
            })
        result["tls_assessment"] = {
            "status": "checked",
            "protocol": tls_version,
            "protocol_status": "weak" if tls_version in WEAK_PROTOCOLS else "acceptable",
            "cipher_status": "weak" if weak_cipher else "acceptable" if cipher else "unavailable",
            "findings": tls_findings,
        }

        certificate_days = metadata["days_remaining"]
        if result["status"] == "valid" and 0 < certificate_days <= 30:
            tls_findings.append({
                "code": "tls_expiring",
                "title": "TLS certificate is expiring soon.",
                "severity": "medium",
                "evidence": f"Certificate expires in {certificate_days} day(s).",
                "source": "certificate_analysis",
                "recommendation": "Renew the certificate before its expiry date and verify automated renewal.",
            })
        tls_findings.extend(_key_or_signature_findings(metadata))

        if not verified_chain:
            result["certificate_chain"]["message"] = (
                "Chain trust was verified during the TLS handshake, but this Python "
                "runtime does not expose the peer chain for display."
            )
        result["trust_intelligence"]["known_distrust"] = {
            "status": "unsupported",
            "message": "No separate known-distrust database is configured.",
        }
        result["trust_intelligence"]["revocation"] = {
            "status": "unsupported",
            "message": "OCSP and CRL revocation checks are not performed.",
        }
        if include_transparency:
            result["trust_intelligence"]["certificate_transparency"] = _transparency_lookup(hostname)
        else:
            result["trust_intelligence"]["certificate_transparency"] = {
                "status": "not_checked",
                "provider": "crt.sh",
                "entry_count": None,
                "entries": [],
                "error": None,
                "message": "Certificate Transparency lookup is skipped for monitoring checks.",
            }
        ct_result = result["trust_intelligence"]["certificate_transparency"]
        if ct_result["status"] == "checked" and ct_result["entry_count"] == 0:
            tls_findings.append({
                "code": "no_ct_entries_found",
                "title": "No matching CT entries were returned by the configured lookup.",
                "severity": "info",
                "evidence": "crt.sh returned zero matching indexed records; the search is partial.",
                "source": "certificate_analysis",
                "recommendation": "Confirm certificate issuance history with the certificate authority; this lookup is not a comprehensive absence proof.",
            })

        if result["status"] == "valid":
            result["findings"] = [
                item["title"]
                for item in tls_findings
                if item.get("severity") != "info"
            ]
            result["finding_details"] = tls_findings
        return result

    except ValueError as error:
        if "non-public" in str(error):
            result.update(status="blocked", error=str(error))
        else:
            result.update(status="invalid_url", error="Invalid URL or certificate data.")
    except socket.gaierror:
        result.update(status="unavailable", error="Could not resolve hostname.")
    except socket.timeout:
        result.update(status="unavailable", error="TLS connection timed out.")
    except (http.client.HTTPException, OSError, ssl.SSLError):
        result.update(status="unavailable", error="Certificate analysis failed.")
    except Exception:
        logger.exception("Unexpected certificate analysis failure.")
        result.update(status="unavailable", error="Certificate analysis failed.")
    return result
