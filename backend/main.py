
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import ipaddress
import re
import dns.resolver
import dns.exception

from services.ml_predictor import predict_url
from services.scan_service import run_full_scan


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

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL is too long")

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            raise ValueError("Invalid scheme")

        if not parsed.hostname:
            raise ValueError("Missing hostname")

        if parsed.username or parsed.password:
            raise ValueError("Credentials are not allowed")

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Enter a valid HTTP or HTTPS URL"
        )

    return run_full_scan(url)


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
