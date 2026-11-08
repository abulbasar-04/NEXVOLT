
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import ipaddress
import re
import sys
from pathlib import Path

import dns.resolver
import dns.exception

# =========================================================
# PROJECT PATH
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# =========================================================
# PROJECT MODULES
# =========================================================

from services.ml_predictor import predict_url

from intelligence import (
    analyze_certificate,
    analyze_threat_intelligence,
)

# =========================================================
# FASTAPI CONFIGURATION
# =========================================================

app = FastAPI(
    title="NEXVOLT API",
    description="AI-powered Web Trust Intelligence Platform",
    version="2.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# REQUEST MODEL
# =========================================================

class ScanRequest(BaseModel):
    url: str


# =========================================================
# URL VALIDATION
# =========================================================

def validate_url(url: str):

    url = url.strip()

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty",
        )

    if len(url) > 2048:
        raise HTTPException(
            status_code=400,
            detail="URL is too long",
        )

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Invalid scheme")

        if not parsed.hostname:
            raise ValueError("Missing hostname")

        # Accessing port can raise ValueError
        _ = parsed.port

        hostname = parsed.hostname.lower()

        if not hostname:
            raise ValueError("Invalid hostname")

        return url, parsed, hostname

    except (ValueError, UnicodeError):
        raise HTTPException(
            status_code=400,
            detail="Enter a valid HTTP or HTTPS URL",
        )


# =========================================================
# RISK CALCULATION
# =========================================================

def calculate_final_risk(
    heuristic_score: int,
    phishing_probability: float,
):

    heuristic_score = max(
        0,
        min(int(heuristic_score), 100),
    )

    phishing_probability = max(
        0.0,
        min(float(phishing_probability), 100.0),
    )

    final_score = max(
        heuristic_score,
        round(phishing_probability),
    )

    final_score = min(final_score, 100)

    if final_score >= 80:
        verdict = "High Risk"

    elif final_score >= 50:
        verdict = "Suspicious"

    elif final_score >= 25:
        verdict = "Moderate Risk"

    else:
        verdict = "Low Risk"

    return final_score, verdict


# =========================================================
# HEURISTIC ANALYSIS
# =========================================================

def analyze_url_heuristics(url: str, parsed, host: str):

    score = 0
    findings = []

    def add_finding(points, message):
        nonlocal score

        score += points
        findings.append(message)

    # HTTP check
    if parsed.scheme == "http":

        add_finding(
            15,
            "Website uses HTTP instead of HTTPS.",
        )

    # IP address check
    try:

        ipaddress.ip_address(host)

        add_finding(
            25,
            "Website uses an IP address instead of a domain.",
        )

    except ValueError:
        pass

    # Suspicious hostname keywords
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "banking",
        "wallet",
        "signin",
        "confirm",
    ]

    for keyword in suspicious_keywords:

        if re.search(
            rf"(^|[.-]){re.escape(keyword)}([.-]|$)",
            host,
        ):

            add_finding(
                10,
                f"Suspicious keyword detected: {keyword}",
            )

            break

    # URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
    ]

    if host in shorteners:

        add_finding(
            20,
            "URL uses a link-shortening service.",
        )

    # Subdomain count
    if len(host.split(".")) > 4:

        add_finding(
            15,
            "Website contains an unusually large number of subdomains.",
        )

    # @ symbol
    if "@" in url:

        add_finding(
            20,
            "URL contains an @ symbol that may hide its real destination.",
        )

    # Punycode
    if "xn--" in host:

        add_finding(
            20,
            "Domain contains Punycode encoding.",
        )

    # Multiple hyphens
    if host.count("-") >= 3:

        add_finding(
            10,
            "Domain contains multiple hyphens.",
        )

    # Dangerous extensions
    dangerous_extensions = (
        ".exe",
        ".apk",
        ".scr",
        ".bat",
        ".cmd",
    )

    if parsed.path.lower().endswith(dangerous_extensions):

        add_finding(
            25,
            "URL points to a potentially dangerous executable file.",
        )

    return min(score, 100), findings


# =========================================================
# ROOT API
# =========================================================

@app.get("/")
def root():

    return {
        "project": "NEXVOLT",
        "message": "Web Trust Intelligence API is running",
        "status": "online",
    }


# =========================================================
# HEALTH API
# =========================================================

@app.get("/api/health")
def health():

    return {
        "status": "healthy",
        "service": "NEXVOLT Backend",
    }


# =========================================================
# URL SCANNER API
# =========================================================

@app.post("/api/scan")
def scan_url(request: ScanRequest):

    # Validate URL
    url, parsed, host = validate_url(request.url)

    # 1. Heuristic analysis
    heuristic_score, findings = analyze_url_heuristics(
        url,
        parsed,
        host,
    )

    # 2. Machine learning prediction
    try:

        ml_result = predict_url(url)

        if not isinstance(ml_result, dict):
            raise ValueError("ML predictor returned invalid response")

        phishing_probability = float(
            ml_result.get("phishing_probability", 0)
        )

        legitimate_probability = float(
            ml_result.get("legitimate_probability", 0)
        )

        ml_prediction = ml_result.get(
            "prediction",
            "Unknown",
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Machine learning prediction failed: {str(e)}",
        )

    # 3. Final risk calculation
    final_risk_score, verdict = calculate_final_risk(
        heuristic_score,
        phishing_probability,
    )

    # 4. ML finding
    if phishing_probability >= 70:

        findings.append(
            f"Machine learning detected high phishing probability: "
            f"{phishing_probability:.2f}%"
        )

    # 5. Final response
    return {
        "url": url,

        "risk_score": final_risk_score,
        "verdict": verdict,

        "heuristic_score": heuristic_score,
        "findings": findings,

        "ml_prediction": {
            "prediction": ml_prediction,
            "phishing_probability": phishing_probability,
            "legitimate_probability": legitimate_probability,
        },

        "analysis": {
            "scheme": parsed.scheme,
            "domain": host,
            "uses_https": parsed.scheme == "https",
        },

        "message": "URL heuristic and ML analysis completed.",

        "note": (
            "Preliminary assessment based on heuristic analysis "
            "and machine learning. This is not a definitive "
            "phishing detection."
        ),
    }


# =========================================================
# SSL CERTIFICATE ANALYSIS API
# =========================================================

@app.get("/api/certificate")
def certificate_analysis(url: str):

    validated_url, parsed, host = validate_url(url)

    try:

        result = analyze_certificate(validated_url)

        return result

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Certificate analysis failed: {str(e)}",
        )


# =========================================================
# THREAT INTELLIGENCE API
# =========================================================

@app.get("/api/threat-intelligence")
def threat_intelligence(url: str):

    validated_url, parsed, host = validate_url(url)

    try:

        result = analyze_threat_intelligence(validated_url)

        return result

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Threat intelligence analysis failed: {str(e)}",
        )


# =========================================================
# DNS LOOKUP API
# =========================================================

@app.get("/api/dns")
def dns_lookup(domain: str):

    domain = domain.strip().lower()

    if not domain or len(domain) > 253:

        raise HTTPException(
            status_code=400,
            detail="Invalid domain",
        )

    if "/" in domain or "://" in domain:

        raise HTTPException(
            status_code=400,
            detail="Enter domain only, not a complete URL",
        )

    if not re.fullmatch(
        r"[a-z0-9.-]+",
        domain,
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid domain format",
        )

    if (
        domain.startswith(".")
        or domain.endswith(".")
        or ".." in domain
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid domain format",
        )

    records = {}

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
    ]

    for record_type in record_types:

        try:

            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=5,
            )

            records[record_type] = [
                str(answer)
                for answer in answers
            ]

        except dns.resolver.NXDOMAIN:

            raise HTTPException(
                status_code=404,
                detail="Domain does not exist",
            )

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):

            records[record_type] = []

        except Exception:

            records[record_type] = []

    return {
        "domain": domain,
        "dns_records": records,
        "message": "DNS lookup completed",
    }


# =========================================================
# UNIFIED WEB TRUST ANALYSIS API
# =========================================================

@app.post("/api/security-analysis")
def unified_security_analysis(request: ScanRequest):

    url, parsed, host = validate_url(request.url)

    # 1. AI + ML URL Scan
    url_scan = scan_url(
        ScanRequest(url=url)
    )

    # 2. SSL Certificate Analysis
    if parsed.scheme == "https":

        try:

            certificate = analyze_certificate(url)

        except Exception as e:

            certificate = {
                "status": "error",
                "error": str(e),
            }

    else:

        certificate = {
            "status": "skipped",
            "message": "HTTPS is required for certificate analysis.",
        }

    # 3. URLhaus Threat Intelligence
    try:

        threat_result = analyze_threat_intelligence(url)

    except Exception as e:

        threat_result = {
            "status": "error",
            "error": str(e),
        }

    # 4. Confirmed threat override
    # Only override if threat result explicitly indicates a match.
    if isinstance(threat_result, dict):

        threat_text = str(threat_result).lower()

        threat_confirmed = (
            threat_result.get("found") is True
            or threat_result.get("is_malicious") is True
            or threat_result.get("listed") is True
        )

        if threat_confirmed:

            url_scan["risk_score"] = 100
            url_scan["verdict"] = "High Risk"

            url_scan["findings"].append(
                "URL is listed in threat intelligence."
            )

    # 5. Combined response
    return {
        "url": url,

        "url_scan": url_scan,

        "certificate_analysis": certificate,

        "threat_intelligence": threat_result,

        "final_risk_score": url_scan["risk_score"],
        "final_verdict": url_scan["verdict"],

        "message": "Unified Web Trust Analysis completed.",
    }
