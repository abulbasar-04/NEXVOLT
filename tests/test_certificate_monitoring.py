import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from services import certificate_monitor
from main import app


def certificate(
    fingerprint="a" * 64,
    issuer=None,
    sans=None,
    not_before=None,
    expires_at=None,
    status="valid",
    key_fingerprint="1" * 64,
):
    now = datetime.now(timezone.utc)
    return {
        "status": status,
        "sha256_fingerprint": fingerprint,
        "issuer": issuer or {"commonName": "Test CA"},
        "subject": {"commonName": "example.com"},
        "serial_number": "01ab",
        "public_key": {
            "algorithm": "RSA",
            "key_size": 2048,
            "sha256_fingerprint": key_fingerprint,
        },
        "not_before": (not_before or now - timedelta(days=10)).isoformat(),
        "expires_at": (expires_at or now + timedelta(days=30)).isoformat(),
        "subject_alt_names": sans or [{"type": "DNS", "value": "example.com"}],
    }


def setup_monitor(monkeypatch, tmp_path, *results):
    monkeypatch.setattr(
        certificate_monitor,
        "DATABASE_PATH",
        tmp_path / "certificate-monitor.sqlite3",
    )
    remaining = list(results)
    calls = []

    def fake_analyze(url, include_transparency=True):
        calls.append(url)
        assert include_transparency is False
        if not remaining:
            raise AssertionError("Unexpected certificate analysis call.")
        return remaining.pop(0)

    monkeypatch.setattr(certificate_monitor, "analyze_certificate", fake_analyze)
    return calls


def test_first_observation_creates_a_baseline_without_alert(monkeypatch, tmp_path):
    calls = setup_monitor(monkeypatch, tmp_path, certificate())

    added = certificate_monitor.add_monitored_domain("EXAMPLE.com")

    assert added["created"] is True
    assert calls == ["https://example.com/"]
    assert added["observation"]["change_type"] == "baseline"
    assert added["observation"]["evidence"] == [
        "First certificate observation; baseline created."
    ]
    assert certificate_monitor.list_certificate_alerts() == []
    assert added["domain"]["latest_observation"]["serial_number"] == "01ab"
    assert added["observation"]["sha256_fingerprint"] == "a" * 64
    assert added["observation"]["issuer"] == {"commonName": "Test CA"}
    assert added["observation"]["public_key"]["algorithm"] == "RSA"
    assert added["observation"]["san_domains"] == [
        {"type": "DNS", "value": "example.com"}
    ]


def test_duplicate_domain_is_not_added_or_rechecked(monkeypatch, tmp_path):
    calls = setup_monitor(monkeypatch, tmp_path, certificate())

    first = certificate_monitor.add_monitored_domain("example.com")
    duplicate = certificate_monitor.add_monitored_domain("EXAMPLE.COM")

    assert first["created"] is True
    assert duplicate["created"] is False
    assert duplicate["domain"]["id"] == first["domain"]["id"]
    assert len(calls) == 1
    assert len(certificate_monitor.list_monitored_domains()) == 1


def test_unchanged_certificate_is_recorded_without_alert(monkeypatch, tmp_path):
    setup_monitor(monkeypatch, tmp_path, certificate(), certificate())

    added = certificate_monitor.add_monitored_domain("example.com")
    observation = certificate_monitor.check_domain(added["domain"]["id"])

    assert observation["change_type"] == "unchanged"
    assert observation["sha256_fingerprint"] == "a" * 64
    assert certificate_monitor.list_certificate_alerts() == []
    history = certificate_monitor.get_domain_history(added["domain"]["id"])
    assert [item["change_type"] for item in history["observations"]] == [
        "unchanged",
        "baseline",
    ]


def test_normal_renewal_is_distinguished_from_suspicious_changes(monkeypatch, tmp_path):
    now = datetime.now(timezone.utc)
    old_expiry = now + timedelta(days=20)
    new_certificate = certificate(
        fingerprint="b" * 64,
        not_before=now - timedelta(days=2),
        expires_at=now + timedelta(days=80),
        key_fingerprint="2" * 64,
    )
    setup_monitor(
        monkeypatch,
        tmp_path,
        certificate(expires_at=old_expiry),
        new_certificate,
    )

    added = certificate_monitor.add_monitored_domain("example.com")
    renewed = certificate_monitor.check_domain(added["domain"]["id"])

    assert renewed["change_type"] == "renewal"
    assert renewed["severity"] == "low"
    assert "Certificate public key changed." in renewed["evidence"]
    alerts = certificate_monitor.list_certificate_alerts()
    assert len(alerts) == 1
    assert alerts[0]["change_type"] == "renewal"
    assert alerts[0]["detected_at"] == renewed["observed_at"]


@pytest.mark.parametrize(
    ("changed", "expected_evidence"),
    [
        (
            {"issuer": {"commonName": "Unexpected CA"}},
            "Certificate issuer changed from",
        ),
        (
            {"sans": [{"type": "DNS", "value": "other.example"}]},
            "Added SAN entries: other.example.",
        ),
    ],
)
def test_issuer_and_san_changes_raise_review_alerts(
    monkeypatch,
    tmp_path,
    changed,
    expected_evidence,
):
    setup_monitor(
        monkeypatch,
        tmp_path,
        certificate(),
        certificate(fingerprint="c" * 64, **changed),
    )

    added = certificate_monitor.add_monitored_domain("example.com")
    observation = certificate_monitor.check_domain(added["domain"]["id"])

    assert observation["change_type"] == "potentially_suspicious"
    assert observation["severity"] == "medium"
    assert any(expected_evidence in item for item in observation["evidence"])
    assert "does not establish malicious activity" in observation["recommendation"]
    assert len(certificate_monitor.list_certificate_alerts()) == 1


def test_unavailable_domain_does_not_create_a_baseline_or_change_alert(
    monkeypatch,
    tmp_path,
):
    setup_monitor(
        monkeypatch,
        tmp_path,
        {"status": "unavailable", "error": "TLS connection timed out."},
        {"status": "unavailable", "error": "TLS connection timed out."},
    )

    added = certificate_monitor.add_monitored_domain("example.com")
    unavailable = added["observation"]
    retried = certificate_monitor.check_domain(added["domain"]["id"])

    assert unavailable["status"] == "unavailable"
    assert unavailable["sha256_fingerprint"] is None
    assert unavailable["change_type"] == "unavailable"
    assert retried["change_type"] == "unavailable"
    assert certificate_monitor.list_certificate_alerts() == []
    history = certificate_monitor.get_domain_history(added["domain"]["id"])
    assert len(history["observations"]) == 2
    assert all(item["sha256_fingerprint"] is None for item in history["observations"])


def test_validity_gap_is_flagged_as_a_potentially_suspicious_change(
    monkeypatch,
    tmp_path,
):
    now = datetime.now(timezone.utc)
    setup_monitor(
        monkeypatch,
        tmp_path,
        certificate(expires_at=now + timedelta(days=10)),
        certificate(
            fingerprint="d" * 64,
            not_before=now + timedelta(days=12),
            expires_at=now + timedelta(days=90),
        ),
    )

    added = certificate_monitor.add_monitored_domain("example.com")
    observation = certificate_monitor.check_domain(added["domain"]["id"])

    assert observation["change_type"] == "potentially_suspicious"
    assert any("validity starts after the previous certificate expired" in item
               for item in observation["evidence"])


def test_san_comparison_is_case_and_order_insensitive():
    previous = certificate_monitor._sanitize_certificate(certificate(
        sans=[
            {"type": "DNS", "value": "EXAMPLE.com"},
            {"type": "DNS", "value": "www.example.com"},
        ],
    ))
    current = certificate_monitor._sanitize_certificate(certificate(
        fingerprint="b" * 64,
        sans=[
            {"type": "DNS", "value": "www.example.com"},
            {"type": "DNS", "value": "example.com"},
        ],
        expires_at=datetime.now(timezone.utc) + timedelta(days=90),
    ))

    assert certificate_monitor._classify_change(previous, current)[0] == "renewal"


def test_certificate_monitor_api_lifecycle(monkeypatch, tmp_path):
    setup_monitor(monkeypatch, tmp_path, certificate(), certificate())

    async def exercise_routes():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as client:
            added = await client.post(
                "/api/certificate-monitoring",
                json={"domain": "example.com"},
            )
            listed = await client.get("/api/certificate-monitoring")
            history = await client.get(
                f"/api/certificate-monitoring/{added.json()['domain']['id']}/history"
            )
            removed = await client.delete(
                f"/api/certificate-monitoring/{added.json()['domain']['id']}"
            )
            invalid = await client.post(
                "/api/certificate-monitoring",
                json={"domain": "https://example.com"},
            )
        return added, listed, history, removed, invalid

    added, listed, history, removed, invalid = asyncio.run(exercise_routes())

    assert added.status_code == 200
    assert added.json()["observation"]["change_type"] == "baseline"
    assert len(listed.json()["domains"]) == 1
    assert len(history.json()["observations"]) == 1
    assert removed.json() == {"removed": True}
    assert invalid.status_code == 400


@pytest.mark.parametrize("value", ["https://example.com", "localhost", "a..example.com", "example.com:443"])
def test_monitor_input_requires_a_domain_only(value):
    with pytest.raises(ValueError):
        certificate_monitor.normalize_domain(value)
