import http.client
import socket

from security_engine import website_scanner
from services.risk_engine import calculate_final_risk


def response(url, headers=None, cookies=None, redirects=None, body=b"", status=200, truncated=False):
    return {
        "status": "completed",
        "http_status": status,
        "final_url": url,
        "headers": headers or {},
        "set_cookie_headers": cookies or [],
        "redirects": redirects or [],
        "body": body,
        "body_truncated": truncated,
        "error": None,
    }


def test_missing_security_headers_are_reported_as_missing_protection(monkeypatch):
    monkeypatch.setattr(website_scanner, "_request_chain", lambda url: response(url))

    result = website_scanner.scan_website("https://example.com/")

    assert result["security_header_status"] == "checked"
    assert set(result["security_headers"]) == set(website_scanner.SECURITY_HEADERS)
    assert all(value is False for value in result["security_headers"].values())
    missing = [
        item for item in result["finding_details"]
        if item["code"].startswith("missing_")
    ]
    assert len(missing) == len(website_scanner.SECURITY_HEADERS)
    assert all(item["classification"] == "missing_protection" for item in missing)
    assert all(item["recommendation"] for item in missing)
    assert "Content-Security-Policy" in next(
        item["recommendation"] for item in missing
        if item["code"] == "missing_content_security_policy"
    )
    assert "vulnerability" not in " ".join(item["title"] for item in missing).lower()


def test_secure_cookies_are_reported_without_values_or_cookie_findings(monkeypatch):
    monkeypatch.setattr(
        website_scanner,
        "_request_chain",
        lambda url: response(
            url,
            headers={"content-type": "text/plain"},
            cookies=["session=never-store; Secure; HttpOnly; SameSite=Lax"],
        ),
    )

    result = website_scanner.scan_website("https://example.com/")

    assert result["cookies"] == [{
        "name": "session",
        "secure": True,
        "http_only": True,
        "same_site": "Lax",
    }]
    assert "never-store" not in str(result)
    assert not any(item["code"].startswith("cookie_") for item in result["finding_details"])


def test_cookie_findings_are_aggregated_by_missing_attribute(monkeypatch):
    monkeypatch.setattr(
        website_scanner,
        "_request_chain",
        lambda url: response(
            url,
            headers={"content-type": "text/plain"},
            cookies=[
                "first=value-a",
                "second=value-b",
                "third=value-c; HttpOnly",
            ],
        ),
    )

    result = website_scanner.scan_website("https://example.com/")
    by_code = {
        finding["code"]: finding for finding in result["finding_details"]
        if finding["code"].startswith("cookie_")
    }

    assert len(by_code) == 3
    assert "first" in by_code["cookie_missing_secure"]["evidence"]
    assert "second" in by_code["cookie_missing_secure"]["evidence"]
    assert "value-a" not in str(by_code)
    assert result["risk_score"] == 90


def test_redirect_chain_records_cross_domain_and_suspicious_public_ip(monkeypatch):
    chain = [
        {
            "from": "https://example.com/",
            "to": "https://8.8.8.8/login",
            "status": 302,
        },
    ]

    def fake_chain(url):
        if url.startswith("https://"):
            return response(
                "https://8.8.8.8/login",
                redirects=chain,
            )
        return response(
            url,
            redirects=[{
                "from": "http://example.com/",
                "to": "https://example.com/",
                "status": 301,
            }],
            status=301,
        )

    monkeypatch.setattr(website_scanner, "_request_chain", fake_chain)

    result = website_scanner.scan_website("https://example.com/")

    assert result["redirect_analysis"]["count"] == 1
    assert result["redirect_analysis"]["cross_origin_count"] == 1
    assert result["redirect_analysis"]["suspicious_patterns"] == [{
        "type": "redirect_to_ip_address",
        "hostname": "8.8.8.8",
    }]
    findings = {item["code"]: item for item in result["finding_details"]}
    assert findings["cross_origin_redirect"]["classification"] == "observed_behavior"
    assert findings["suspicious_redirect_destination"]["recommendation"]


def test_redirect_loop_is_detected_and_returned_with_evidence(monkeypatch):
    monkeypatch.setattr(website_scanner, "validate_url", lambda _url: True)
    monkeypatch.setattr(
        website_scanner,
        "_request_once",
        lambda url: {
            "http_status": 302,
            "headers": {"location": "/"},
            "set_cookie_headers": [],
            "body": b"",
            "body_truncated": False,
        },
    )

    result = website_scanner.scan_website("https://example.com/")

    assert result["status"] == "redirect_loop"
    assert result["redirect_analysis"]["loop_detected"] is True
    finding = next(
        item for item in result["finding_details"]
        if item["code"] == "redirect_loop_detected"
    )
    assert finding["classification"] == "confirmed_configuration_issue"
    assert finding["evidence"]


def test_redirect_to_private_address_is_blocked_without_request(monkeypatch):
    requests = []

    def resolve(hostname, port, type):
        address = "8.8.8.8" if hostname == "example.com" else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]

    def request(url):
        requests.append(url)
        if url.startswith("http://"):
            return {
                "http_status": 301,
                "headers": {"location": "https://example.com/"},
                "set_cookie_headers": [],
                "body": b"",
                "body_truncated": False,
            }
        return {
            "http_status": 302,
            "headers": {"location": "http://127.0.0.1/admin"},
            "set_cookie_headers": [],
            "body": b"",
            "body_truncated": False,
        }

    monkeypatch.setattr(website_scanner.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(website_scanner, "_request_once", request)

    result = website_scanner.scan_website("https://example.com/")

    assert result["status"] == "blocked"
    assert requests == ["https://example.com/"]
    assert any(item["code"] == "redirect_target_blocked" for item in result["finding_details"])


def test_mixed_content_and_http_form_destinations_are_reported(monkeypatch):
    body = (
        b"<html><script src='http://assets.example/script.js'></script>"
        b"<img src='http://images.example/logo.png'>"
        b"<style>.hero { background: url('http://styles.example/hero.jpg'); }</style>"
        b"<form action='http://submit.example/login'></form></html>"
    )

    def fake_chain(url):
        if url.startswith("http://"):
            return response(
                "https://example.com/",
                redirects=[{
                    "from": url,
                    "to": "https://example.com/",
                    "status": 301,
                }],
                status=301,
            )
        return response(
            url,
            headers={"content-type": "application/xhtml+xml; charset=utf-8"},
            body=body,
        )

    monkeypatch.setattr(website_scanner, "_request_chain", fake_chain)

    result = website_scanner.scan_website("https://example.com/")

    assert result["mixed_content"]["status"] == "checked"
    assert {item["hostname"] for item in result["mixed_content"]["resources"]} == {
        "assets.example",
        "images.example",
        "styles.example",
    }
    assert result["mixed_content"]["insecure_forms"] == ["submit.example"]
    codes = {item["code"] for item in result["finding_details"]}
    assert "mixed_content_detected" in codes
    assert "insecure_form_action" in codes


def test_truncated_html_is_explicitly_a_partial_mixed_content_check(monkeypatch):
    monkeypatch.setattr(
        website_scanner,
        "_request_chain",
        lambda url: response(
            url,
            headers={"content-type": "text/html"},
            body=b"<html>",
            truncated=True,
        ),
    )

    result = website_scanner.scan_website("https://example.com/")

    assert result["mixed_content"]["status"] == "partial"
    assert result["mixed_content"]["truncated"] is True
    assert not any(
        item["code"] == "mixed_content_detected"
        for item in result["finding_details"]
    )


def test_mixed_content_reference_reporting_is_bounded():
    body = (
        "<html>"
        + "".join(
            f"<img src='http://asset-{index}.example/image.png'>"
            for index in range(website_scanner.MAX_REPORTED_PAGE_REFERENCES + 5)
        )
        + "</html>"
    ).encode()

    result = website_scanner._inspect_page_html(
        "https://example.com/",
        "text/html",
        "",
        body,
        False,
    )

    assert result["status"] == "partial"
    assert result["resource_count"] == website_scanner.MAX_REPORTED_PAGE_REFERENCES + 5
    assert len(result["resources"]) == website_scanner.MAX_REPORTED_PAGE_REFERENCES


def test_timeout_and_unavailable_checks_are_not_reported_as_safe(monkeypatch):
    def timeout(_url):
        raise socket.timeout("timed out")

    monkeypatch.setattr(website_scanner, "_request_chain", timeout)

    result = website_scanner.scan_website("https://example.com/")
    score = calculate_final_risk(
        ml_result={},
        phishing_result={},
        threat_result={"status": "unavailable"},
        certificate_result={"status": "unavailable"},
        website_result=result,
    )

    assert result["status"] == "unavailable"
    assert result["risk_score"] is None
    assert result["security_header_status"] == "unavailable"
    assert result["https_enforcement"]["status"] == "unavailable"
    assert result["mixed_content"]["status"] == "unavailable"
    assert score["score_breakdown"]["website_security_risk_score"] is None
    assert score["score_explanation"]["components"][-1]["status"] == "unavailable"


def test_risk_engine_keeps_website_evidence_and_deduplicates_findings():
    finding = {
        "code": "mixed_content_detected",
        "title": "HTTPS page references one or more HTTP resources.",
        "severity": "high",
        "evidence": "Two insecure resource references were observed.",
        "source": "website_assessment",
        "classification": "confirmed_insecure_resource_reference",
    }
    result = calculate_final_risk(
        ml_result={},
        phishing_result={},
        threat_result={},
        certificate_result={},
        website_result={
            "status": "completed",
            "risk_score": 30,
            "finding_details": [finding, dict(finding)],
        },
    )

    assert result["score_breakdown"]["website_security_risk_score"] == 30
    matches = [
        item for item in result["finding_details"]
        if item["code"] == "mixed_content_detected"
    ]
    assert len(matches) == 1
    assert matches[0]["evidence"] == finding["evidence"]
    assert matches[0]["recommendation"]


def test_oversized_html_is_read_only_to_the_scanner_limit(monkeypatch):
    class FakeResponse:
        status = 200

        def getheaders(self):
            return [("Content-Type", "text/html")]

        def read(self, size):
            assert size == website_scanner.MAX_HTML_BYTES + 1
            return b"x" * size

        def close(self):
            pass

    class FakeConnection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, method, path, headers):
            assert method == "GET"
            assert headers["Range"] == f"bytes=0-{website_scanner.MAX_HTML_BYTES}"
            assert "Cookie" not in headers

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(website_scanner, "_resolve_public_addresses", lambda *_args: [(
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        ("8.8.8.8", 443),
    )])
    monkeypatch.setattr(website_scanner, "_PinnedHTTPConnection", FakeConnection)

    result = website_scanner._request_once("https://example.com/")

    assert len(result["body"]) == website_scanner.MAX_HTML_BYTES
    assert result["body_truncated"] is True


def test_website_scan_network_timeout_from_http_client_is_unavailable(monkeypatch):
    def timeout(_url):
        raise http.client.IncompleteRead(b"")

    monkeypatch.setattr(website_scanner, "_request_chain", timeout)

    result = website_scanner.scan_website("https://example.com/")

    assert result["status"] == "unavailable"
    assert result["security_header_status"] == "unavailable"
