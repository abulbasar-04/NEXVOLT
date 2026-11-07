
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import ipaddress
import re
import dns.resolver
import dns.exception

from services.ml_predictor import predict_url


# =========================================================
# NEXVOLT API CONFIGURATION
# =========================================================

app = FastAPI(
    title="NEXVOLT API",
    description="AI-powered Web Trust Intelligence Platform",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
# URL SCANNER
# =========================================================

class ScanRequest(BaseModel):
    url: str


@app.post("/api/scan")
def scan_url(request: ScanRequest):

    url = request.url.strip()

    # Empty URL validation
    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty"
        )

    # URL length validation
    if len(url) > 2048:
        raise HTTPException(
            status_code=400,
            detail="URL is too long"
        )

    # URL format validation
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            raise ValueError("Invalid scheme")

        if not parsed.hostname:
            raise ValueError("Missing hostname")

        host = parsed.hostname.lower()

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Enter a valid HTTP or HTTPS URL"
        )

    # =====================================================
    # HEURISTIC ANALYSIS
    # =====================================================

    score = 0
    findings = []

    def add_finding(points, message):
        nonlocal score
        score += points
        findings.append(message)

    # HTTP security check
    if parsed.scheme == "http":
        add_finding(
            15,
            "Website uses HTTP instead of HTTPS."
        )

    # IP address check
    try:
        ipaddress.ip_address(host)

        add_finding(
            25,
            "Website uses an IP address instead of a domain."
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
            host
        ):
            add_finding(
                10,
                f"Suspicious keyword detected: {keyword}"
            )
            break

    # URL shortener check
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
            "URL uses a link-shortening service."
        )

    # Subdomain check
    if len(host.split(".")) > 4:
        add_finding(
            15,
            "Website contains an unusually large number of subdomains."
        )

    # @ symbol check
    if "@" in url:
        add_finding(
            20,
            "URL contains an @ symbol that may hide its real destination."
        )

    # Punycode check
    if "xn--" in host:
        add_finding(
            20,
            "Domain contains Punycode encoding."
        )

    # Hyphen check
    if host.count("-") >= 3:
        add_finding(
            10,
            "Domain contains multiple hyphens."
        )

    # Dangerous file extension check
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
            "URL points to a potentially dangerous executable file."
        )

    # Heuristic risk score
    score = min(score, 100)

    if score >= 60:
        verdict = "Dangerous"

    elif score >= 30:
        verdict = "Suspicious"

    else:
        verdict = "Low Risk"

    # =====================================================
    # MACHINE LEARNING PREDICTION
    # =====================================================

    ml_result = predict_url(url)

    # =====================================================
    # FINAL SCAN RESPONSE
    # =====================================================

    return {
        "url": url,

        "risk_score": score,
        "verdict": verdict,
        "findings": findings,

        "ml_prediction": ml_result,

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
# DNS LOOKUP API
# =========================================================

@app.get("/api/dns")
def dns_lookup(domain: str):

    domain = domain.strip().lower()

    if not domain or len(domain) > 253:
        raise HTTPException(
            status_code=400,
            detail="Invalid domain"
        )

    if "/" in domain or "://" in domain:
        raise HTTPException(
            status_code=400,
            detail="Enter domain only, not a complete URL"
        )

    # Domain format validation
    if not re.fullmatch(
        r"[a-z0-9.-]+",
        domain
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain format"
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
                detail="Domain does not exist"
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
