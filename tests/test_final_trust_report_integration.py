import pytest
from fastapi.testclient import TestClient

from main import app
from services import scan_service


@pytest.fixture
def api_client():
    with TestClient(app) as client:
        yield client


def _unavailable(_url):
    raise RuntimeError("test-only unavailable analyzer")


def test_health_endpoint_identifies_cybernova(api_client):
    response = api_client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "CYBERNOVA Backend",
    }


def test_scan_api_preserves_schema_and_unknown_when_analysis_sources_fail(
    api_client,
    monkeypatch,
):
    monkeypatch.setattr(scan_service, "predict_url", _unavailable)
    monkeypatch.setattr(scan_service, "detect_phishing", _unavailable)
    monkeypatch.setattr(scan_service, "check_threat_intelligence", _unavailable)
    monkeypatch.setattr(scan_service, "scan_website", _unavailable)
    monkeypatch.setattr(scan_service, "analyze_certificate", _unavailable)

    response = api_client.post(
        "/api/scan",
        json={"url": "https://example.com/"},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["risk_score"] is None
    assert result["trust_score"] is None
    assert result["risk_category"] == "Unknown"
    assert result["verdict"] == "Unknown"
    assert set(result["score_breakdown"]) == {
        "ml_probability",
        "rule_based_score",
        "threat_intelligence_score",
        "certificate_risk_score",
        "website_security_risk_score",
    }
    assert all(value is None for value in result["score_breakdown"].values())
    assert result["ml_prediction"]["status"] == "unavailable"
    assert result["phishing_analysis"]["status"] == "unavailable"
    assert result["threat_intelligence"]["status"] == "unavailable"
    assert result["certificate_analysis"]["status"] == "unavailable"
    assert result["website_analysis"]["status"] == "unavailable"
    assert result["score_explanation"]["coverage_percent"] == 0


def test_confirmed_external_source_dominates_scan_score_and_keeps_attribution(
    api_client,
    monkeypatch,
):
    monkeypatch.setattr(
        scan_service,
        "predict_url",
        lambda _url: {
            "status": "available",
            "model_source": "test fixture",
            "phishing_probability": 2.0,
            "legitimate_probability": 98.0,
            "prediction": "Legitimate",
        },
    )
    monkeypatch.setattr(
        scan_service,
        "detect_phishing",
        lambda _url: {"status": "completed", "risk_score": 0, "findings": []},
    )
    monkeypatch.setattr(
        scan_service,
        "check_threat_intelligence",
        lambda url: {
            "url": url,
            "status": "malicious",
            "confirmed_malicious": True,
            "checked_at": "2026-11-09T00:00:00+00:00",
            "urlhaus": {
                "source": "URLhaus",
                "status": "malicious",
                "malicious": True,
                "category": "malware_distribution",
                "confidence": "high",
                "checked_at": "2026-11-09T00:00:00+00:00",
                "details": {},
            },
            "sources": {
                "urlhaus": {
                    "source": "URLhaus",
                    "status": "malicious",
                    "malicious": True,
                    "category": "malware_distribution",
                    "confidence": "high",
                    "checked_at": "2026-11-09T00:00:00+00:00",
                    "details": {},
                },
                "community": {
                    "source": "Community reports",
                    "status": "unverified",
                    "malicious": False,
                    "details": {
                        "report_count": 1,
                        "distinct_reporters": 1,
                        "reviewed_reporters": 0,
                        "categories": {"phishing": 1},
                    },
                },
            },
            "findings": [{
                "title": "Confirmed malware distribution threat reported.",
                "category": "malware_distribution",
                "severity": "critical",
                "evidence": "URLhaus returned an exact URL match.",
                "sources": ["URLhaus"],
                "recommendation": "Do not visit or download.",
            }],
        },
    )
    monkeypatch.setattr(
        scan_service,
        "scan_website",
        lambda url: {
            "status": "completed",
            "final_url": url,
            "risk_score": 0,
            "finding_details": [],
            "findings": [],
            "security_headers": {},
        },
    )
    monkeypatch.setattr(
        scan_service,
        "analyze_certificate",
        lambda url: {
            "url": url,
            "status": "valid",
            "valid": True,
            "hostname_match": True,
            "verification": {
                "validity_dates": "verified",
                "hostname": "verified",
                "chain": "verified",
                "status": "verified",
            },
            "finding_details": [],
        },
    )

    response = api_client.post(
        "/api/scan",
        json={"url": "https://example.com/login"},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["risk_score"] == 100
    assert result["trust_score"] == 0
    assert result["risk_category"] == "Critical"
    assert result["verdict"] == "Malicious"
    assert result["threat_intelligence"]["sources"]["community"]["status"] == "unverified"
    assert result["finding_details"][0]["source"] == "URLhaus"
    assert set(result["score_breakdown"]) == {
        "ml_probability",
        "rule_based_score",
        "threat_intelligence_score",
        "certificate_risk_score",
        "website_security_risk_score",
    }


def test_certificate_monitoring_is_not_a_scan_risk_component(api_client, monkeypatch):
    monkeypatch.setattr(
        scan_service,
        "predict_url",
        lambda _url: {"status": "unavailable"},
    )
    monkeypatch.setattr(
        scan_service,
        "detect_phishing",
        lambda _url: {"status": "unavailable"},
    )
    monkeypatch.setattr(
        scan_service,
        "check_threat_intelligence",
        lambda _url: {
            "status": "unavailable",
            "confirmed_malicious": False,
            "urlhaus": {"status": "unavailable"},
            "sources": {
                "urlhaus": {"status": "unavailable"},
                "community": {"status": "unavailable", "details": {}},
            },
        },
    )
    monkeypatch.setattr(
        scan_service,
        "scan_website",
        lambda _url: {"status": "unavailable"},
    )
    monkeypatch.setattr(
        scan_service,
        "analyze_certificate",
        lambda _url: {"status": "unavailable"},
    )

    result = api_client.post(
        "/api/scan",
        json={"url": "https://example.com/"},
    ).json()

    assert "certificate_monitoring" not in result["score_breakdown"]
    assert "certificate_change_score" not in result["score_breakdown"]
    assert result["risk_score"] is None
    assert result["verdict"] == "Unknown"


@pytest.mark.parametrize(
    ("payload", "status_code"),
    [
        ({}, 422),
        ({"url": "ftp://example.com"}, 400),
        ({"url": "https://user:pass@example.com/"}, 400),
    ],
)
def test_scan_api_validates_request_contract(api_client, payload, status_code):
    response = api_client.post("/api/scan", json=payload)

    assert response.status_code == status_code
