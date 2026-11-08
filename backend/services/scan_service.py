import logging
from urllib.parse import urlparse

from services.ml_predictor import predict_url
from services.risk_engine import calculate_final_risk

from security_engine.phishing_detector import detect_phishing
from security_engine.website_scanner import scan_website

from intelligence.threat_intelligence import check_threat_intelligence
from intelligence.certificate_analyzer import analyze_certificate


logger = logging.getLogger(__name__)


def _run_analysis(source: str, analyzer, url: str) -> dict:
    try:
        result = analyzer(url)
        if not isinstance(result, dict):
            raise TypeError(f"{source} analyzer returned a non-object result.")
        return result
    except Exception:
        logger.exception("%s analysis failed.", source)
        return {
            "status": "unavailable",
            "error": f"{source} analysis failed; see server logs for details.",
        }


def run_full_scan(url: str) -> dict:
    parsed = urlparse(url)

    # 1. Machine Learning Prediction
    ml_result = _run_analysis("ML", predict_url, url)

    # 2. Rule-Based Phishing Detection
    phishing_result = _run_analysis("Rule-based", detect_phishing, url)

    # 3. Threat Intelligence
    threat_result = _run_analysis("Threat intelligence", check_threat_intelligence, url)

    # 4. Website Security Scanner
    website_result = _run_analysis("Website security", scan_website, url)

    # 5. SSL Certificate Analysis
    certificate_url = url
    final_url = website_result.get("final_url")
    if (
        website_result.get("status") == "completed"
        and final_url
        and urlparse(final_url).scheme == "https"
    ):
        certificate_url = final_url

    if urlparse(certificate_url).scheme == "https":
        certificate_result = _run_analysis(
            "TLS certificate",
            analyze_certificate,
            certificate_url,
        )
    else:
        certificate_result = {
            "url": certificate_url,
            "status": "not_https",
            "valid": False,
            "hostname_match": False,
            "error": "HTTPS is not used.",
        }
    certificate_result["requested_url"] = url

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
        "trust_score": risk_result["trust_score"],
        "risk_category": risk_result["risk_category"],
        "verdict": risk_result["verdict"],
        "findings": risk_result["findings"],
        "finding_details": risk_result["finding_details"],
        "score_breakdown": risk_result["score_breakdown"],
        "score_explanation": risk_result["score_explanation"],
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
