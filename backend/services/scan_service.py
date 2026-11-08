from urllib.parse import urlparse

from services.ml_predictor import predict_url
from services.risk_engine import calculate_final_risk

from security_engine.phishing_detector import detect_phishing
from security_engine.website_scanner import scan_website

from intelligence.threat_intelligence import check_threat_intelligence
from intelligence.certificate_analyzer import analyze_certificate


def run_full_scan(url: str) -> dict:
    parsed = urlparse(url)

    # 1. Machine Learning Prediction
    ml_result = predict_url(url)

    # 2. Rule-Based Phishing Detection
    phishing_result = detect_phishing(url)

    # 3. Threat Intelligence (URLhaus)
    threat_result = check_threat_intelligence(url)

    # 4. SSL Certificate Analysis
    if parsed.scheme == "https":
        certificate_result = analyze_certificate(url)
    else:
        certificate_result = {
            "status": "not_https",
            "valid": False,
            "error": "HTTPS is not used.",
        }

    # 5. Website Security Scanner
    website_result = scan_website(url)

    # 6. Unified Risk Engine
    risk_result = calculate_final_risk(
        ml_result=ml_result,
        phishing_result=phishing_result,
        threat_result=threat_result,
        certificate_result=certificate_result,
        website_result=website_result,
    )

    return {
        "url": url,
        "risk_score": risk_result["risk_score"],
        "verdict": risk_result["verdict"],
        "findings": risk_result["findings"],
        "score_breakdown": risk_result["score_breakdown"],
        "ml_prediction": ml_result,
        "phishing_analysis": phishing_result,
        "threat_intelligence": threat_result,
        "certificate_analysis": certificate_result,
        "website_analysis": website_result,
        "analysis": {
            "scheme": parsed.scheme,
            "domain": parsed.hostname,
            "uses_https": parsed.scheme == "https",
        },
        "message": "Full security analysis completed.",
        "note": (
            "Automated security assessment. "
            "Low Risk does not guarantee a website is completely safe."
        ),
    }
