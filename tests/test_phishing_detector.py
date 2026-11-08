import pytest

from security_engine.phishing_detector import detect_phishing


def test_safe_url():
    result = detect_phishing("https://google.com")

    assert result["risk_score"] == 0
    assert result["reasons"] == []


def test_suspicious_ip_url():
    result = detect_phishing(
        "http://192.168.1.1/login/verify"
    )

    assert result["risk_score"] == 45
    assert "URL uses an IP address instead of a domain." in result["reasons"]


def test_high_risk_ip_url():
    result = detect_phishing(
        "http://192.168.1.1:8080/login/verify/account"
    )

    assert result["risk_score"] == 45
    assert len(result["reasons"]) >= 2


def test_multiple_suspicious_keywords():
    result = detect_phishing(
        "http://secure-login-verify.example.com/account"
    )

    assert result["risk_score"] == 35
    assert len(result["reasons"]) == 3


def test_empty_url():
    result = detect_phishing("")

    assert result["risk_score"] == 100
    assert "Invalid hostname" in result["reasons"]
