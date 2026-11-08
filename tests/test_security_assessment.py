import json
import socket
import ssl
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from intelligence import certificate_analyzer
from intelligence.certificate_analyzer import analyze_certificate
from security_engine import phishing_detector, website_scanner
from services.feature_extraction import extract_url_features
from services.ml_predictor import model, predict_url
from services.risk_engine import calculate_final_risk
from services import scan_service


def verified_certificate(**overrides):
    result = {
        "status": "valid",
        "valid": True,
        "verification": {
            "status": "verified",
            "validity_dates": "verified",
            "hostname": "verified",
            "chain": "verified",
        },
    }
    result.update(overrides)
    return result


def make_test_certificate(hostname="example.com", not_before=None, not_after=None):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((not_before or now - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((not_after or now + timedelta(days=90)).replace(tzinfo=None))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.DER)


class FakeSecureSocket:
    def __init__(
        self,
        certificate_der,
        protocol="TLSv1.3",
        cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        verified_chain=None,
    ):
        self.certificate_der = certificate_der
        self.protocol = protocol
        self.negotiated_cipher = cipher
        self.verified_chain = verified_chain

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def getpeercert(self, binary_form=False):
        return self.certificate_der if binary_form else {}

    def version(self):
        return self.protocol

    def cipher(self):
        return self.negotiated_cipher

    def get_verified_chain(self):
        return self.verified_chain


class FakeTLSContext:
    def __init__(
        self,
        certificate_der=None,
        error=None,
        protocol="TLSv1.3",
        cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        verified_chain=None,
    ):
        self.certificate_der = certificate_der
        self.error = error
        self.protocol = protocol
        self.negotiated_cipher = cipher
        self.verified_chain = verified_chain

    def wrap_socket(self, _raw_socket, server_hostname):
        assert server_hostname == "example.com"
        if self.error:
            raise self.error
        return FakeSecureSocket(
            self.certificate_der,
            self.protocol,
            self.negotiated_cipher,
            self.verified_chain,
        )


class FakeRawSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


def mock_certificate_connection(monkeypatch, context):
    monkeypatch.setattr(
        "intelligence.certificate_analyzer.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        ],
    )
    monkeypatch.setattr(
        "intelligence.certificate_analyzer.socket.create_connection",
        lambda *_args, **_kwargs: FakeRawSocket(),
    )
    monkeypatch.setattr(
        "intelligence.certificate_analyzer.ssl.create_default_context",
        lambda: context,
    )
    monkeypatch.setattr(
        "intelligence.certificate_analyzer._transparency_lookup",
        lambda _hostname: {
            "status": "checked",
            "provider": "crt.sh",
            "coverage": "partial",
            "entries": [],
            "entry_count": 0,
            "error": None,
        },
    )


def test_ml_probability_comes_from_loaded_model():
    url = "https://example.com/security-review-model-check"
    features = pd.DataFrame([extract_url_features(url)])
    expected = model.predict_proba(features)[0]
    classes = list(model.classes_)

    actual = predict_url(url)

    assert actual["model_source"] == "trained_model"
    assert actual["prediction"] == (
        "Phishing" if model.predict(features)[0] == 0 else "Legitimate"
    )
    assert actual["phishing_probability"] == round(
        float(expected[classes.index(0)]) * 100, 2
    )
    assert actual["legitimate_probability"] == round(
        float(expected[classes.index(1)]) * 100, 2
    )


def test_rule_based_score_is_derived_from_recorded_findings():
    actual = phishing_detector.detect_phishing(
        "http://192.0.2.10/login/verify"
    )

    assert actual["risk_score"] == 45
    assert actual["reasons"] == [
        finding["title"] for finding in actual["findings"]
    ]
    assert {finding["source"] for finding in actual["findings"]} == {
        "rule_based"
    }


def test_unavailable_threat_feed_is_excluded_from_explainable_score():
    result = calculate_final_risk(
        ml_result={"phishing_probability": 20, "model_source": "trained_model"},
        phishing_result={"risk_score": 30, "findings": []},
        threat_result={"urlhaus": {"status": "unavailable", "malicious": False}},
        certificate_result=verified_certificate(),
        website_result={"status": "completed", "risk_score": 10, "finding_details": []},
    )

    assert result["score_breakdown"]["threat_intelligence_score"] is None
    assert result["risk_score"] == 19.38
    assert result["trust_score"] == 80.62
    assert result["score_explanation"]["coverage_percent"] == 80
    threat_component = next(
        item for item in result["score_explanation"]["components"]
        if item["key"] == "threat_intelligence_score"
    )
    assert threat_component["status"] == "unavailable"
    assert threat_component["effective_weight"] == 0


def test_scan_response_adds_trust_explanation_without_removing_api_fields(monkeypatch):
    monkeypatch.setattr(
        scan_service,
        "predict_url",
        lambda _url: {
            "prediction": "Legitimate",
            "phishing_probability": 12.5,
            "legitimate_probability": 87.5,
            "model_source": "trained_model",
        },
    )
    monkeypatch.setattr(
        scan_service,
        "detect_phishing",
        lambda _url: {"risk_score": 5, "reasons": [], "findings": []},
    )
    monkeypatch.setattr(
        scan_service,
        "check_threat_intelligence",
        lambda _url: {
            "urlhaus": {
                "status": "not_found",
                "malicious": False,
                "details": None,
                "error": None,
            }
        },
    )
    monkeypatch.setattr(
        scan_service,
        "analyze_certificate",
        lambda target: {
            "url": target,
            **verified_certificate(),
            "hostname_match": True,
            "days_remaining": 90,
        },
    )
    monkeypatch.setattr(
        scan_service,
        "scan_website",
        lambda _url: {
            "status": "completed",
            "final_url": "https://example.com/",
            "findings": [],
            "finding_details": [],
            "risk_score": 0,
        },
    )

    actual = scan_service.run_full_scan("http://example.com/")

    assert {
        "url",
        "risk_score",
        "risk_category",
        "verdict",
        "findings",
        "score_breakdown",
        "ml_prediction",
        "threat_intelligence",
        "certificate_analysis",
        "website_analysis",
        "analysis",
        "message",
        "note",
    }.issubset(actual)
    assert actual["trust_score"] == round(100 - actual["risk_score"], 2)
    assert actual["score_explanation"]["components"]
    assert actual["ml_prediction"]["model_source"] == "trained_model"
    assert actual["certificate_analysis"]["url"] == "https://example.com/"


def test_confirmed_urlhaus_match_is_highest_risk():
    result = calculate_final_risk(
        ml_result={"phishing_probability": 0},
        phishing_result={"risk_score": 0, "findings": []},
        threat_result={"urlhaus": {"status": "malicious", "malicious": True}},
        certificate_result=verified_certificate(),
        website_result={"status": "completed", "risk_score": 0, "finding_details": []},
    )

    assert result["risk_score"] == 100
    assert result["trust_score"] == 0
    assert result["verdict"] == "Malicious"
    assert result["finding_details"][0]["source"] == "URLhaus"


def test_risk_categories_follow_documented_boundaries():
    cases = [
        (0, "Low"),
        (34.99, "Low"),
        (35, "Medium"),
        (64.99, "Medium"),
        (65, "High"),
        (84.99, "High"),
        (85, "Critical"),
        (100, "Critical"),
    ]

    for score, category in cases:
        result = calculate_final_risk(
            ml_result={"phishing_probability": score, "model_source": "trained_model"},
            phishing_result={},
            threat_result={},
            certificate_result={},
            website_result={},
        )

        assert result["risk_score"] == score
        assert result["risk_category"] == category
        assert result["verdict"] != category


def test_unavailable_sources_produce_unknown_not_a_fabricated_risk_score():
    result = calculate_final_risk(
        ml_result={"status": "unavailable"},
        phishing_result={"status": "unavailable"},
        threat_result={"urlhaus": {"status": "unavailable", "malicious": False}},
        certificate_result={"status": "unavailable"},
        website_result={"status": "unavailable"},
    )

    assert result["risk_score"] is None
    assert result["trust_score"] is None
    assert result["risk_category"] == "Unknown"
    assert result["verdict"] == "Unknown"
    assert result["score_explanation"]["coverage_percent"] == 0
    assert "No numeric score is reported" in result["score_explanation"]["method"]


def test_out_of_range_component_is_unavailable_not_clamped_to_a_score():
    result = calculate_final_risk(
        ml_result={"phishing_probability": 120, "model_source": "trained_model"},
        phishing_result={},
        threat_result={},
        certificate_result={},
        website_result={},
    )

    assert result["risk_score"] is None
    assert result["score_breakdown"]["ml_probability"] is None


def test_unverified_ml_probability_is_not_counted_as_a_model_result():
    result = calculate_final_risk(
        ml_result={"phishing_probability": 0},
        phishing_result={},
        threat_result={},
        certificate_result={},
        website_result={},
    )

    assert result["risk_score"] is None
    assert result["score_breakdown"]["ml_probability"] is None
    assert result["score_explanation"]["components"][0]["status"] == "unverified_source"


def test_findings_include_evidence_severity_and_actionable_recommendation():
    result = calculate_final_risk(
        ml_result={"phishing_probability": 50, "model_source": "trained_model"},
        phishing_result={
            "risk_score": 30,
            "findings": [{
                "title": "Domain contains a sensitive login-related keyword.",
                "severity": "low",
                "evidence": "Hostname contains: login.",
                "source": "rule_based",
            }],
        },
        threat_result={"urlhaus": {"status": "unavailable", "malicious": False}},
        certificate_result={
            "status": "expired",
            "error": "The certificate is expired.",
        },
        website_result={
            "status": "completed",
            "risk_score": 15,
            "finding_details": [{
                "code": "missing_content_security_policy",
                "title": "CSP response header is missing.",
                "severity": "medium",
                "evidence": "Final response did not include content-security-policy.",
                "source": "website_assessment",
            }],
        },
    )

    assert result["risk_category"] == "Medium"
    assert all(finding.get("severity") for finding in result["finding_details"])
    assert all(finding.get("evidence") for finding in result["finding_details"])
    assert all(finding.get("recommendation") for finding in result["finding_details"])
    assert any(
        "certificate" in finding["recommendation"].lower()
        for finding in result["finding_details"]
    )


def test_scan_service_keeps_other_results_when_an_analysis_source_fails(monkeypatch):
    def fail_ml(_url):
        raise RuntimeError("model process unavailable")

    monkeypatch.setattr(scan_service, "predict_url", fail_ml)
    monkeypatch.setattr(
        scan_service,
        "detect_phishing",
        lambda _url: {"risk_score": 10, "findings": []},
    )
    monkeypatch.setattr(
        scan_service,
        "check_threat_intelligence",
        lambda _url: {"urlhaus": {"status": "unavailable", "malicious": False}},
    )
    monkeypatch.setattr(
        scan_service,
        "analyze_certificate",
        lambda _url: {"status": "valid", "valid": True},
    )
    monkeypatch.setattr(
        scan_service,
        "scan_website",
        lambda _url: {"status": "unavailable", "risk_score": None},
    )

    result = scan_service.run_full_scan("https://example.com/")

    assert result["ml_prediction"]["status"] == "unavailable"
    assert result["risk_score"] == 10
    assert result["risk_category"] == "Low"


def test_website_scan_reports_header_cookie_and_https_evidence(monkeypatch):
    def fake_request_chain(requested_url):
        if requested_url.startswith("http://"):
            return {
                "status": "completed",
                "http_status": 301,
                "final_url": "https://example.com/",
                "headers": {},
                "set_cookie_headers": [],
                "redirects": [{
                    "from": "http://example.com/",
                    "to": "https://example.com/",
                    "status": 301,
                }],
                "error": None,
            }
        return {
            "status": "completed",
            "http_status": 200,
            "final_url": requested_url,
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            },
            "set_cookie_headers": ["session=secret; HttpOnly; SameSite=None"],
            "redirects": [],
            "error": None,
        }

    monkeypatch.setattr(website_scanner, "validate_url", lambda _url: True)
    monkeypatch.setattr(website_scanner, "_request_chain", fake_request_chain)

    result = website_scanner.scan_website("https://example.com/")

    assert result["status"] == "completed"
    assert result["https_enforced"] is True
    assert result["security_headers"]["x-frame-options"] is False
    assert "X-Frame-Options" not in result["missing_headers"]
    assert result["cookies"] == [{
        "name": "session",
        "secure": False,
        "http_only": True,
        "same_site": "None",
    }]
    assert "session=secret" not in str(result["cookies"])
    assert "cookie_samesite_none_without_secure" in {
        finding["code"] for finding in result["finding_details"]
    }


def test_website_scan_blocks_non_public_dns_results(monkeypatch):
    monkeypatch.setattr(
        website_scanner.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        ],
    )

    result = website_scanner.scan_website("https://example.com/")

    assert result["status"] == "blocked"
    assert "non-public" in result["error"]


def test_tls_expiry_verification_error_is_reported_as_expired(monkeypatch):
    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    class FakeContext:
        def wrap_socket(self, _raw_socket, server_hostname):
            assert server_hostname == "example.com"
            raise ssl.SSLCertVerificationError(10, "certificate has expired")

    monkeypatch.setattr(
        "intelligence.certificate_analyzer.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(0, 0, 0, "", ("8.8.8.8", 443))],
    )
    monkeypatch.setattr(
        "intelligence.certificate_analyzer.socket.create_connection",
        lambda *_args, **_kwargs: FakeSocket(),
    )
    monkeypatch.setattr(
        "intelligence.certificate_analyzer.ssl.create_default_context",
        lambda: FakeContext(),
    )
    expired_der = make_test_certificate(
        not_before=datetime.now(timezone.utc) - timedelta(days=90),
        not_after=datetime.now(timezone.utc) - timedelta(days=1),
    )
    monkeypatch.setattr(
        "intelligence.certificate_analyzer._inspect_unverified_peer",
        lambda *_args: (
            expired_der,
            "TLSv1.3",
            ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        ),
    )

    result = analyze_certificate("https://example.com/")

    assert result["status"] == "expired"
    assert result["valid"] is False
    assert result["verification"]["validity_dates"] == "failed"
    assert result["finding_details"][0]["code"] == "tls_expired"
    assert result["not_before"] is not None
    assert result["expires_at"] is not None
    assert result["certificate_metadata_status"] == "observed_unverified"


def test_certificate_transparency_lookup_returns_partial_issuance_records(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def raise_for_status(self):
            return None

        def iter_bytes(self):
            yield json.dumps([{
                "id": 123,
                "issuer_name": "Example CA",
                "not_before": "2026-01-01",
                "not_after": "2027-01-01",
                "name_value": "example.com",
            }]).encode()

    monkeypatch.setattr(
        "intelligence.certificate_analyzer.httpx.stream",
        lambda *_args, **_kwargs: FakeResponse(),
    )

    result = certificate_analyzer._transparency_lookup("example.com")

    assert result["status"] == "checked"
    assert result["coverage"] == "partial"
    assert result["entry_count"] == 1
    assert result["entries"][0]["issuer"] == "Example CA"


def test_certificate_analysis_reports_validity_and_tls_metadata(monkeypatch):
    certificate_der = make_test_certificate()
    mock_certificate_connection(
        monkeypatch,
        FakeTLSContext(certificate_der=certificate_der),
    )

    result = analyze_certificate("https://example.com/")

    assert result["status"] == "valid"
    assert result["valid"] is True
    assert result["verification"]["validity_dates"] == "verified"
    assert result["verification"]["hostname"] == "verified"
    assert result["verification"]["chain"] == "verified"
    assert result["certificate_chain"]["status"] == "unsupported"
    assert result["certificate_chain"]["verification"] == "verified"
    assert result["public_key"] == {
        "status": "verified",
        "algorithm": "RSA",
        "key_size": 2048,
        "sha256_fingerprint": result["public_key"]["sha256_fingerprint"],
    }
    assert len(result["public_key"]["sha256_fingerprint"]) == 64
    expected_fingerprint = x509.load_der_x509_certificate(certificate_der).fingerprint(
        hashes.SHA256()
    ).hex()
    assert result["sha256_fingerprint"] == expected_fingerprint
    assert result["serial_number"]
    assert result["signature"]["algorithm"] == "sha256"
    assert result["tls_version"] == "TLSv1.3"
    assert result["trust_intelligence"]["certificate_transparency"]["status"] == "checked"
    assert result["trust_intelligence"]["revocation"]["status"] == "unsupported"


def test_certificate_analysis_includes_verified_chain_when_runtime_exposes_it(monkeypatch):
    leaf_der = make_test_certificate()
    chain_certificate = x509.load_der_x509_certificate(leaf_der)
    mock_certificate_connection(
        monkeypatch,
        FakeTLSContext(
            certificate_der=leaf_der,
            verified_chain=[chain_certificate],
        ),
    )

    result = analyze_certificate("https://example.com/")

    assert result["certificate_chain"]["status"] == "available"
    assert result["certificate_chain"]["verification"] == "verified"
    assert len(result["certificate_chain"]["certificates"]) == 1
    assert result["certificate_chain"]["certificates"][0]["subject"]["commonName"] == "example.com"


def test_certificate_analysis_flags_weak_negotiated_protocol_and_cipher(monkeypatch):
    mock_certificate_connection(
        monkeypatch,
        FakeTLSContext(
            certificate_der=make_test_certificate(),
            protocol="TLSv1",
            cipher=("NULL-MD5", "TLSv1", 40),
        ),
    )

    result = analyze_certificate("https://example.com/")
    finding_codes = {item["code"] for item in result["finding_details"]}

    assert result["status"] == "valid"
    assert result["tls_assessment"]["protocol_status"] == "weak"
    assert result["tls_assessment"]["cipher_status"] == "weak"
    assert {"weak_tls_protocol", "weak_tls_cipher"}.issubset(finding_codes)


def test_certificate_analysis_flags_weak_public_key(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=30)).replace(tzinfo=None))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    mock_certificate_connection(
        monkeypatch,
        FakeTLSContext(certificate_der=certificate.public_bytes(Encoding.DER)),
    )

    result = analyze_certificate("https://example.com/")

    assert result["public_key"]["key_size"] == 1024
    assert any(
        item["code"] == "weak_certificate_key"
        for item in result["finding_details"]
    )


@pytest.mark.parametrize(
    ("message", "expected_status", "expected_check"),
    [
        ("Hostname mismatch for example.com", "invalid", "hostname"),
        ("unable to get local issuer certificate", "invalid", "chain"),
    ],
)
def test_certificate_validation_failures_are_distinguished(
    monkeypatch,
    message,
    expected_status,
    expected_check,
):
    mock_certificate_connection(
        monkeypatch,
        FakeTLSContext(error=ssl.SSLCertVerificationError(message)),
    )

    result = analyze_certificate("https://example.com/")

    assert result["status"] == expected_status
    assert result["valid"] is False
    assert result["verification"]["status"] == "failed"
    assert result["verification"][expected_check] == "failed"
    assert result["finding_details"]


def test_self_signed_certificate_is_identified(monkeypatch):
    mock_certificate_connection(
        monkeypatch,
        FakeTLSContext(error=ssl.SSLCertVerificationError("self-signed certificate")),
    )

    result = analyze_certificate("https://example.com/")

    assert result["status"] == "invalid"
    assert result["verification"]["self_signed"] == "detected"
    assert result["finding_details"][0]["code"] == "self_signed_certificate"


def test_unavailable_certificate_analysis_does_not_claim_valid(monkeypatch):
    monkeypatch.setattr(
        "intelligence.certificate_analyzer.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        ],
    )
    def timeout(*_args, **_kwargs):
        raise socket.timeout()

    monkeypatch.setattr(
        "intelligence.certificate_analyzer.socket.create_connection",
        timeout,
    )

    result = analyze_certificate("https://example.com/")

    assert result["status"] == "unavailable"
    assert result["valid"] is False
    assert result["verification"]["status"] == "unavailable"


def test_expired_leaf_certificate_dates_are_detected(monkeypatch):
    now = datetime.now(timezone.utc)
    certificate_der = make_test_certificate(
        not_before=now - timedelta(days=90),
        not_after=now - timedelta(days=2),
    )
    mock_certificate_connection(
        monkeypatch,
        FakeTLSContext(certificate_der=certificate_der),
    )

    result = analyze_certificate("https://example.com/")

    assert result["status"] == "expired"
    assert result["valid"] is False
    assert result["verification"]["validity_dates"] == "failed"
    assert result["finding_details"][0]["code"] == "tls_expired"


def test_certificate_findings_are_integrated_into_risk_engine():
    result = calculate_final_risk(
        ml_result={"phishing_probability": 0, "model_source": "trained_model"},
        phishing_result={"risk_score": 0, "findings": []},
        threat_result={"urlhaus": {"status": "unavailable", "malicious": False}},
        certificate_result=verified_certificate(
            finding_details=[{
                "code": "weak_certificate_key",
                "title": "Certificate uses a weak public key.",
                "severity": "high",
                "evidence": "Public key is RSA with 1024 bits.",
                "source": "certificate_analysis",
                "recommendation": "Replace the certificate key.",
            }],
        ),
        website_result={"status": "unavailable"},
    )

    assert result["score_breakdown"]["certificate_risk_score"] == 75
    assert result["risk_score"] == 10.71
    assert result["finding_details"][0]["code"] == "weak_certificate_key"
    assert result["finding_details"][0]["recommendation"] == "Replace the certificate key."
