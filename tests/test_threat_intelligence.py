import json

import httpx

from intelligence import threat_intelligence as intel
from services.risk_engine import calculate_final_risk


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://example.test/")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                "HTTP error",
                request=request,
                response=response,
            )

    def json(self):
        return self.payload


class FakeStreamResponse(FakeResponse):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def iter_bytes(self):
        yield self.payload


def reset_openphish_cache(monkeypatch):
    monkeypatch.setattr(
        intel,
        "_openphish_cache",
        {"expires_at": 0.0, "urls": None, "checked_at": None},
    )


def test_url_normalization_canonicalizes_origin_and_drops_fragment():
    assert intel.normalize_url(
        "HTTPS://ExAmPle.com:443/a%2Fb?next=%2Fhome#section"
    ) == "https://example.com/a%2Fb?next=%2Fhome"
    assert intel.normalize_domain("ExAmPle.com.") == "example.com"


def test_url_normalization_rejects_credentials_and_non_http_schemes():
    for value in ("https://user:pass@example.com/", "ftp://example.com/"):
        try:
            intel.normalize_url(value)
        except ValueError:
            continue
        raise AssertionError(f"Expected invalid URL to be rejected: {value}")


def test_urlhaus_confirmed_exact_match_includes_source_and_report_time(monkeypatch):
    monkeypatch.setattr(intel, "URLHAUS_AUTH_KEY", "test-key")
    monkeypatch.setattr(
        intel.httpx,
        "post",
        lambda *_args, **_kwargs: FakeResponse({
            "query_status": "ok",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
            "url": "https://example.com/bad",
            "url_status": "online",
            "threat": "malware_download",
            "date_added": "2026-11-01 10:00:00 UTC",
            "tags": ["payload"],
            "reporter": "test-feed",
        }),
    )

    result = intel.check_urlhaus("https://EXAMPLE.com:443/bad#fragment")

    assert result["status"] == "malicious"
    assert result["malicious"] is True
    assert result["queried_url"] == "https://example.com/bad"
    assert result["category"] == "malware_distribution"
    assert result["confidence"] == "high"
    assert result["source"] == "URLhaus"
    assert result["reported_at"] == "2026-11-01 10:00:00 UTC"
    assert result["checked_at"]


def test_urlhaus_not_found_is_distinct_from_unavailable(monkeypatch):
    monkeypatch.setattr(intel, "URLHAUS_AUTH_KEY", "test-key")
    monkeypatch.setattr(
        intel.httpx,
        "post",
        lambda *_args, **_kwargs: FakeResponse({"query_status": "no_results"}),
    )

    result = intel.check_urlhaus("https://example.com/")

    assert result["status"] == "not_found"
    assert result["malicious"] is False
    assert result["confidence"] is None


def test_urlhaus_missing_key_is_unavailable_without_request(monkeypatch):
    monkeypatch.setattr(intel, "URLHAUS_AUTH_KEY", None)
    monkeypatch.setattr(
        intel.httpx,
        "post",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected call")),
    )

    result = intel.check_urlhaus("https://example.com/")

    assert result["status"] == "unavailable"
    assert "API key" in result["error"]


def test_urlhaus_timeout_is_unavailable(monkeypatch):
    monkeypatch.setattr(intel, "URLHAUS_AUTH_KEY", "test-key")

    def timeout(*_args, **_kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(intel.httpx, "post", timeout)

    result = intel.check_urlhaus("https://example.com/")

    assert result["status"] == "unavailable"
    assert "timed out" in result["error"]


def test_phishtank_confirmed_result_requires_verified_and_valid(monkeypatch):
    monkeypatch.setattr(intel, "PHISHTANK_API_KEY", "test-key")
    monkeypatch.setattr(
        intel.httpx,
        "post",
        lambda *_args, **_kwargs: FakeResponse({
            "results": {
                "in_database": True,
                "verified": True,
                "valid": True,
                "phish_id": "123",
                "phish_detail_page": "https://www.phishtank.com/phish_detail.php?phish_id=123",
                "target": "Example Bank",
                "submission_time": "2026-11-02 10:00:00",
            },
        }),
    )

    result = intel.check_phishtank("https://example.com/login")

    assert result["status"] == "malicious"
    assert result["category"] == "phishing"
    assert result["confidence"] == "high"
    assert result["reported_at"] == "2026-11-02 10:00:00"


def test_phishtank_unverified_record_is_unknown_not_confirmed(monkeypatch):
    monkeypatch.setattr(intel, "PHISHTANK_API_KEY", "test-key")
    monkeypatch.setattr(
        intel.httpx,
        "post",
        lambda *_args, **_kwargs: FakeResponse({
            "results": {"in_database": True, "verified": False, "valid": True},
        }),
    )

    result = intel.check_phishtank("https://example.com/login")

    assert result["status"] == "unknown"
    assert result["malicious"] is False


def test_openphish_matches_public_feed_and_caches_lookup(monkeypatch):
    reset_openphish_cache(monkeypatch)
    calls = []

    def fake_stream(*_args, **_kwargs):
        calls.append(True)
        return FakeStreamResponse(
            b"https://example.com/login\nhttps://other.example/path\n"
        )

    monkeypatch.setattr(intel.httpx, "stream", fake_stream)

    first = intel.check_openphish("https://EXAMPLE.com/login#fragment")
    second = intel.check_openphish("https://example.com/login")

    assert first["status"] == "malicious"
    assert first["category"] == "phishing"
    assert first["source"] == "OpenPhish"
    assert first["checked_at"]
    assert second["status"] == "malicious"
    assert len(calls) == 1


def test_openphish_timeout_is_unavailable_and_not_found_is_not_safety(monkeypatch):
    reset_openphish_cache(monkeypatch)

    def timeout(*_args, **_kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(intel.httpx, "stream", timeout)
    unavailable = intel.check_openphish("https://example.com/")
    assert unavailable["status"] == "unavailable"

    reset_openphish_cache(monkeypatch)
    monkeypatch.setattr(
        intel.httpx,
        "stream",
        lambda *_args, **_kwargs: FakeStreamResponse(b"https://other.example/\n"),
    )
    not_found = intel.check_openphish("https://example.com/")
    assert not_found["status"] == "not_found"
    assert not_found["confidence"] is None


def test_feed_failures_are_independent_and_aggregate_status_is_partial(monkeypatch):
    def failed(_url):
        raise RuntimeError("feed is down")

    monkeypatch.setattr(intel, "check_urlhaus", failed)
    monkeypatch.setattr(
        intel,
        "check_phishtank",
        lambda url: intel._base_result("PhishTank", url, "not_found"),
    )
    monkeypatch.setattr(intel, "check_openphish", failed)

    result = intel.check_threat_intelligence("https://example.com/")

    assert result["status"] == "partial"
    assert result["sources"]["urlhaus"]["status"] == "unavailable"
    assert result["sources"]["phishtank"]["status"] == "not_found"
    assert result["sources"]["openphish"]["status"] == "unavailable"


def test_identical_source_findings_are_deduplicated_with_attribution():
    url = "https://example.com/phish"
    results = {
        "urlhaus": {
            **intel._base_result("URLhaus", url, "malicious"),
            "malicious": True,
            "category": "phishing",
            "confidence": "high",
            "confidence_note": "Exact URL match",
            "details": {"threat": "phishing"},
        },
        "phishtank": {
            **intel._base_result("PhishTank", url, "malicious"),
            "malicious": True,
            "category": "phishing",
            "confidence": "high",
            "confidence_note": "Verified exact URL match",
            "details": {"phish_id": "1"},
        },
    }

    aggregate = intel.aggregate_threat_results(url, results)

    assert aggregate["status"] == "malicious"
    assert aggregate["confirmed_malicious"] is True
    assert len(aggregate["findings"]) == 1
    assert set(aggregate["findings"][0]["sources"]) == {"URLhaus", "PhishTank"}
    assert aggregate["findings"][0]["recommendation"]


def test_all_feed_misses_aggregate_to_not_found_not_safe():
    url = "https://example.com/"
    sources = {
        name: intel._base_result(name, url, "not_found")
        for name in ("URLhaus", "PhishTank", "OpenPhish")
    }

    result = intel.aggregate_threat_results(url, sources)

    assert result["status"] == "not_found"
    assert result["confirmed_malicious"] is False
    assert result["findings"] == []


def test_partial_or_unavailable_feed_results_are_not_scored_as_clean():
    partial = {
        "status": "partial",
        "confirmed_malicious": False,
        "urlhaus": {"status": "not_found", "malicious": False},
        "sources": {
            "urlhaus": {"status": "not_found", "malicious": False},
            "openphish": {"status": "unavailable", "malicious": False},
        },
    }
    unavailable = {
        "status": "unavailable",
        "urlhaus": {"status": "unavailable", "malicious": False},
    }

    for threat in (partial, unavailable):
        risk = calculate_final_risk(
            ml_result={},
            phishing_result={},
            threat_result=threat,
            certificate_result={},
            website_result={},
        )
        assert risk["score_breakdown"]["threat_intelligence_score"] is None
        assert risk["risk_score"] is None


def test_confirmed_aggregate_intelligence_integrates_once_into_risk():
    url = "https://example.com/phish"
    sources = {
        name: {
            **intel._base_result(name, url, "malicious"),
            "malicious": True,
            "category": "phishing",
            "confidence": "high",
            "details": {},
        }
        for name in ("URLhaus", "OpenPhish")
    }
    threat = intel.aggregate_threat_results(url, sources)

    risk = calculate_final_risk(
        ml_result={},
        phishing_result={},
        threat_result=threat,
        certificate_result={},
        website_result={},
    )

    assert risk["score_breakdown"]["threat_intelligence_score"] == 100
    assert risk["risk_score"] == 100
    assert len(risk["finding_details"]) == 1
    assert risk["finding_details"][0]["source"] == "URLhaus, OpenPhish"
    assert risk["finding_details"][0]["recommendation"]


def test_not_found_aggregate_retains_legacy_urlhaus_field_and_only_scores_full_clean():
    url = "https://example.com/"
    sources = {
        name: intel._base_result(name, url, "not_found")
        for name in ("URLhaus", "PhishTank", "OpenPhish")
    }
    threat = intel.aggregate_threat_results(url, sources)

    risk = calculate_final_risk(
        ml_result={},
        phishing_result={},
        threat_result=threat,
        certificate_result={},
        website_result={},
    )

    assert threat["urlhaus"]["status"] == "not_found"
    assert risk["score_breakdown"]["threat_intelligence_score"] == 0
    assert risk["score_explanation"]["components"][2]["status"] == "not_found"
