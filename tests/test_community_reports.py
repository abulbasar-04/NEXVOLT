import pytest
from fastapi.testclient import TestClient

from intelligence import threat_intelligence
from services import community_reports
from services.risk_engine import calculate_final_risk
from main import app


ADMIN_TOKEN = "test-admin-token-that-is-at-least-32-bytes-long"


@pytest.fixture
def reports_client(monkeypatch, tmp_path):
    monkeypatch.setattr(
        community_reports,
        "DATABASE_PATH",
        tmp_path / "community-reports.sqlite3",
    )
    monkeypatch.setattr(community_reports, "_submission_attempts", {})
    monkeypatch.delenv("COMMUNITY_REPORT_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("COMMUNITY_REPORT_COOKIE_SECURE", raising=False)
    with TestClient(app) as client:
        yield client


def report_payload(url="https://Example.com/login#fragment", **overrides):
    return {
        "url": url,
        "category": "phishing",
        "evidence": "Observed a credential prompt.",
        **overrides,
    }


def test_submission_normalizes_url_and_keeps_reporter_private(reports_client):
    session = reports_client.get("/api/community-reports/session")
    assert session.status_code == 200
    cookie = session.cookies.get(community_reports.REPORTER_COOKIE_NAME)
    assert cookie
    assert "httponly" in session.headers["set-cookie"].lower()

    submitted = reports_client.post(
        "/api/community-reports",
        json=report_payload(),
        headers={"origin": "http://localhost:5173"},
    )
    assert submitted.status_code == 201
    assert submitted.json()["url"] == "https://example.com/login"
    assert submitted.json()["domain"] == "example.com"
    assert submitted.json()["status"] == "pending"
    assert "reporter" not in submitted.json()

    public_report = reports_client.get("/api/community-reports").json()["reports"][0]
    assert public_report["category"] == "phishing"
    assert public_report["distinct_reporters"] == 1
    assert "evidence" not in public_report
    assert "reporter_ref" not in public_report
    assert "Observed a credential prompt" not in str(public_report)

    with community_reports._database() as connection:
        stored = connection.execute(
            "SELECT * FROM community_reports"
        ).fetchone()
        assert stored["reporter_ref"] != cookie.split(".")[0]
        assert stored["evidence"] == "Observed a credential prompt."
        assert stored["submitted_at"]


def test_duplicate_report_from_same_reporter_is_rejected(reports_client):
    reports_client.get("/api/community-reports/session")
    first = reports_client.post("/api/community-reports", json=report_payload())
    duplicate = reports_client.post(
        "/api/community-reports",
        json=report_payload(
            url="HTTPS://example.COM:443/login#another-fragment",
            category="scam",
        ),
    )

    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert "already submitted" in duplicate.json()["detail"]
    assert len(reports_client.get("/api/community-reports").json()["reports"]) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://[::1]/",
        "https://router.local/",
        "https://user:pass@example.com/",
        "file:///etc/passwd",
    ],
)
def test_submission_rejects_private_or_invalid_targets(reports_client, url):
    result = reports_client.post(
        "/api/community-reports",
        json=report_payload(url=url),
    )

    assert result.status_code == 400


def test_report_validation_rejects_unknown_categories_and_oversized_evidence(reports_client):
    unsupported = reports_client.post(
        "/api/community-reports",
        json=report_payload(category="credential theft"),
    )
    oversized = reports_client.post(
        "/api/community-reports",
        json=report_payload(evidence="e" * 2001),
    )

    assert unsupported.status_code == 400
    assert oversized.status_code == 422


def test_public_feed_does_not_allow_untrusted_origins(reports_client):
    response = reports_client.post(
        "/api/community-reports",
        json=report_payload(),
        headers={"origin": "https://attacker.example"},
    )

    assert response.status_code == 403


def test_public_feed_redacts_url_query_while_admin_can_review_full_indicator(
    reports_client,
    monkeypatch,
):
    reports_client.get("/api/community-reports/session")
    reports_client.post(
        "/api/community-reports",
        json=report_payload(
            url="https://example.com/login?token=private-secret&campaign=phish"
        ),
    )
    public = reports_client.get("/api/community-reports").json()["reports"][0]

    assert public["url"] == "https://example.com/login"
    assert "private-secret" not in str(public)
    assert "campaign" not in str(public)

    monkeypatch.setenv("COMMUNITY_REPORT_ADMIN_TOKEN", ADMIN_TOKEN)
    admin = reports_client.get(
        "/api/community-reports/admin",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    ).json()["reports"][0]
    assert admin["url"] == (
        "https://example.com/login?token=private-secret&campaign=phish"
    )


def test_report_submission_rate_limit(reports_client, monkeypatch):
    monkeypatch.setattr(community_reports, "RATE_LIMIT_MAX_SUBMISSIONS", 1)
    reports_client.get("/api/community-reports/session")
    first = reports_client.post("/api/community-reports", json=report_payload())
    second = reports_client.post(
        "/api/community-reports",
        json=report_payload(url="https://example.com/other"),
    )

    assert first.status_code == 201
    assert second.status_code == 429
    assert int(second.headers["retry-after"]) > 0


def test_moderation_requires_admin_token_and_records_audit(reports_client, monkeypatch):
    reports_client.get("/api/community-reports/session")
    created = reports_client.post("/api/community-reports", json=report_payload()).json()
    report_id = created["id"]
    rejected_id = reports_client.post(
        "/api/community-reports",
        json=report_payload(url="https://example.com/rejected"),
    ).json()["id"]
    resolved_id = reports_client.post(
        "/api/community-reports",
        json=report_payload(url="https://example.com/resolved"),
    ).json()["id"]

    unauthorized = reports_client.get("/api/community-reports/admin")
    assert unauthorized.status_code == 503

    monkeypatch.setenv("COMMUNITY_REPORT_ADMIN_TOKEN", ADMIN_TOKEN)
    denied = reports_client.get(
        "/api/community-reports/admin",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert denied.status_code == 401

    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    queue = reports_client.get("/api/community-reports/admin", headers=headers)
    assert queue.status_code == 200
    admin_report = queue.json()["reports"][0]
    assert admin_report["evidence"] == "Observed a credential prompt."
    assert "reporter_ref" not in admin_report

    approved = reports_client.post(
        f"/api/community-reports/{report_id}/moderation",
        json={"status": "approved", "note": "Evidence reviewed."},
        headers=headers,
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    duplicate_transition = reports_client.post(
        f"/api/community-reports/{report_id}/moderation",
        json={"status": "rejected"},
        headers=headers,
    )
    assert duplicate_transition.status_code == 409

    rejected = reports_client.post(
        f"/api/community-reports/{rejected_id}/moderation",
        json={"status": "rejected"},
        headers=headers,
    )
    resolved = reports_client.post(
        f"/api/community-reports/{resolved_id}/moderation",
        json={"status": "resolved"},
        headers=headers,
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"
    assert all(
        item["id"] != rejected_id
        for item in reports_client.get("/api/community-reports").json()["reports"]
    )

    with community_reports._database() as connection:
        audit = connection.execute(
            """
            SELECT previous_status, new_status, note
            FROM community_report_moderation WHERE report_id = ?
            """,
            (report_id,),
        ).fetchone()
        assert tuple(audit) == ("pending", "approved", "Evidence reviewed.")

    intelligence = community_reports.lookup_community_reports(created["url"])
    assert intelligence["status"] == "reviewed"
    assert intelligence["malicious"] is False
    assert intelligence["details"]["reviewed_reporters"] == 1


def test_other_reporters_raise_reputation_without_exposing_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(
        community_reports,
        "DATABASE_PATH",
        tmp_path / "community-reports.sqlite3",
    )
    community_reports.submit_report(
        "https://example.com/login",
        "phishing",
        "Evidence one",
        "opaque-reporter-1",
    )
    community_reports.submit_report(
        "https://example.com/login",
        "phishing",
        "Evidence two",
        "opaque-reporter-2",
    )

    intel = community_reports.lookup_community_reports("https://example.com/login")
    feed = community_reports.list_public_reports()

    assert intel["status"] == "unverified"
    assert intel["malicious"] is False
    assert intel["details"]["report_count"] == 2
    assert intel["details"]["distinct_reporters"] == 2
    assert "reporter_ref" not in str(intel)
    assert "opaque-reporter" not in str(feed)


def test_community_intelligence_contributes_conservatively_not_as_confirmation(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        community_reports,
        "DATABASE_PATH",
        tmp_path / "community-reports.sqlite3",
    )
    for reporter in ("reporter-a", "reporter-b"):
        community_reports.submit_report(
            "https://example.com/login",
            "phishing",
            "",
            reporter,
        )
    monkeypatch.setattr(
        threat_intelligence,
        "check_urlhaus",
        lambda url: threat_intelligence._base_result("URLhaus", url, "not_found"),
    )
    monkeypatch.setattr(
        threat_intelligence,
        "check_phishtank",
        lambda url: threat_intelligence._base_result("PhishTank", url, "not_found"),
    )
    monkeypatch.setattr(
        threat_intelligence,
        "check_openphish",
        lambda url: threat_intelligence._base_result("OpenPhish", url, "not_found"),
    )

    result = threat_intelligence.check_threat_intelligence("https://example.com/login")
    risk = calculate_final_risk(
        ml_result={},
        phishing_result={},
        threat_result=result,
        certificate_result={},
        website_result={},
    )

    assert result["status"] == "partial"
    assert result["confirmed_malicious"] is False
    assert result["sources"]["community"]["status"] == "unverified"
    assert risk["score_breakdown"]["threat_intelligence_score"] == 15
    assert risk["verdict"] != "Malicious"
    community_finding = next(
        finding
        for finding in risk["finding_details"]
        if finding["source"] == "Community reports"
    )
    assert community_finding["severity"] == "medium"
    assert "independent" in community_finding["recommendation"]


def test_unavailable_community_database_is_reported_without_breaking_other_feeds(
    monkeypatch,
):
    def failed_lookup(_url):
        raise OSError("database unavailable")

    monkeypatch.setattr(
        community_reports,
        "lookup_community_reports",
        failed_lookup,
    )
    monkeypatch.setattr(
        threat_intelligence,
        "check_urlhaus",
        lambda url: threat_intelligence._base_result("URLhaus", url, "not_found"),
    )
    monkeypatch.setattr(
        threat_intelligence,
        "check_phishtank",
        lambda url: threat_intelligence._base_result("PhishTank", url, "not_found"),
    )
    monkeypatch.setattr(
        threat_intelligence,
        "check_openphish",
        lambda url: threat_intelligence._base_result("OpenPhish", url, "not_found"),
    )

    result = threat_intelligence.check_threat_intelligence("https://example.com/")

    assert result["sources"]["community"]["status"] == "unavailable"
    assert "Community report lookup is unavailable" in result["sources"]["community"]["error"]
    assert result["sources"]["urlhaus"]["status"] == "not_found"


def test_a_single_unverified_report_does_not_raise_score_or_confirm_threat(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        community_reports,
        "DATABASE_PATH",
        tmp_path / "community-reports.sqlite3",
    )
    community_reports.submit_report(
        "https://example.com/login",
        "scam",
        "",
        "one-reporter",
    )
    threat = {
        "status": "partial",
        "confirmed_malicious": False,
        "urlhaus": {"status": "unavailable"},
        "sources": {
            "community": community_reports.lookup_community_reports(
                "https://example.com/login"
            )
        },
    }
    risk = calculate_final_risk(
        ml_result={},
        phishing_result={},
        threat_result=threat,
        certificate_result={},
        website_result={},
    )

    assert risk["score_breakdown"]["threat_intelligence_score"] is None
    assert risk["verdict"] == "Unknown"
    assert risk["finding_details"][0]["source"] == "Community reports"


def test_community_source_cannot_assert_a_confirmed_malicious_verdict():
    community = {
        "source": "Community reports",
        "status": "malicious",
        "malicious": True,
        "details": {
            "report_count": 1,
            "distinct_reporters": 1,
            "reviewed_reporters": 0,
            "categories": {"phishing": 1},
        },
    }
    risk = calculate_final_risk(
        ml_result={},
        phishing_result={},
        threat_result={
            "status": "malicious",
            "confirmed_malicious": True,
            "sources": {"community": community},
            "urlhaus": {"status": "unavailable"},
        },
        certificate_result={},
        website_result={},
    )

    assert risk["verdict"] != "Malicious"


def test_schema_migration_is_versioned_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(
        community_reports,
        "DATABASE_PATH",
        tmp_path / "community-reports.sqlite3",
    )
    community_reports.list_public_reports()
    community_reports.list_public_reports()

    with community_reports._database() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert "community_reports" in tables
    assert "community_report_moderation" in tables
