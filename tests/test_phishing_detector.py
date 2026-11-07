
import pytest

from security_engine.phishing_detector import detect_phishing


def test_safe_url():
    result = detect_phishing("https://google.com")

    assert result["status"] == "Safe"
    assert result["risk_score"] == 0


def test_suspicious_ip_url():
    result = detect_phishing(
        "http://192.168.1.1/login/verify"
    )

    assert result["status"] == "Suspicious"
    assert result["risk_score"] == 50


def test_high_risk_url():
    result = detect_phishing(
        "http://192.168.1.1:8080/login/verify/account"
    )

    assert result["status"] == "High Risk"
    assert result["risk_score"] >= 60


def test_multiple_suspicious_keywords():
    result = detect_phishing(
        "http://secure-login-verify.example.com/account"
    )

    assert result["status"] == "Suspicious"
    assert result["risk_score"] == 35


def test_empty_url():
    with pytest.raises(ValueError):
        detect_phishing("")
