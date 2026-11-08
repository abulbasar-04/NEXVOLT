
from __future__ import annotations

import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from urllib.parse import urlparse
import ipaddress
import re
import dns.resolver
import dns.exception

from services.ml_predictor import predict_url
from services.scan_service import run_full_scan
from services import certificate_monitor
from services import community_reports


logger = logging.getLogger(__name__)


def _certificate_monitor_interval() -> int:
    default_interval = 6 * 60 * 60
    try:
        configured = int(os.getenv("CERTIFICATE_MONITOR_INTERVAL_SECONDS", default_interval))
    except (TypeError, ValueError):
        logger.warning(
            "Invalid CERTIFICATE_MONITOR_INTERVAL_SECONDS; using the six-hour default."
        )
        configured = default_interval
    return max(300, min(configured, 30 * 24 * 60 * 60))


CERTIFICATE_MONITOR_INTERVAL_SECONDS = _certificate_monitor_interval()


async def _certificate_monitor_scheduler():
    while True:
        await asyncio.sleep(CERTIFICATE_MONITOR_INTERVAL_SECONDS)
        try:
            await asyncio.to_thread(certificate_monitor.check_all_monitored_domains)
        except Exception:
            logger.exception("Scheduled certificate monitoring run failed.")


@asynccontextmanager
async def lifespan(application):
    task = asyncio.create_task(_certificate_monitor_scheduler())
    application.state.certificate_monitor_task = task
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# =========================================================
# CYBERNOVA API CONFIGURATION
# =========================================================

app = FastAPI(
    title="CYBERNOVA API",
    description="AI-powered Web Trust Intelligence Platform",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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
        "project": "CYBERNOVA",
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
        "service": "CYBERNOVA Backend",
    }


# =========================================================
# URL SCANNER
# =========================================================

class ScanRequest(BaseModel):
    url: str


class CertificateMonitorRequest(BaseModel):
    domain: str


class CommunityReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048)
    category: str = Field(min_length=1, max_length=40)
    evidence: str = Field(default="", max_length=2000)


class CommunityModerationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["approved", "rejected", "resolved"]
    note: str = Field(default="", max_length=500)


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


def _set_reporter_cookie(response: Response, token: str):
    secure_cookie = os.getenv("COMMUNITY_REPORT_COOKIE_SECURE", "").lower() in {
        "1",
        "true",
        "yes",
    }
    response.set_cookie(
        key=community_reports.REPORTER_COOKIE_NAME,
        value=token,
        max_age=365 * 24 * 60 * 60,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        path="/api/community-reports",
    )


def _require_report_admin(request: Request):
    configured_token = os.getenv("COMMUNITY_REPORT_ADMIN_TOKEN", "")
    if not configured_token.isascii() or not 32 <= len(configured_token) <= 256:
        raise HTTPException(
            status_code=503,
            detail="Community report moderation is not configured on this server.",
        )
    authorization = request.headers.get("authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not supplied_token.isascii()
        or len(supplied_token) > 256
        or not hmac.compare_digest(supplied_token, configured_token)
    ):
        raise HTTPException(status_code=401, detail="Administrator authorization required.")


@app.get("/api/community-reports/session")
def community_report_session(request: Request, response: Response):
    _reporter_ref, token, _is_new = community_reports.ensure_reporter(request)
    _set_reporter_cookie(response, token)
    return {"ready": True}


@app.get("/api/community-reports")
def get_community_reports(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
):
    return {"reports": community_reports.list_public_reports(limit, offset)}


@app.get("/api/community-reports/verified")
def get_verified_community_reports(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
):
    return {"reports": community_reports.list_verified_reports(limit, offset)}


@app.post("/api/community-reports", status_code=201)
def submit_community_report(
    report: CommunityReportRequest,
    request: Request,
    response: Response,
):
    origin = request.headers.get("origin")
    if origin and origin not in {
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    }:
        raise HTTPException(status_code=403, detail="Report submissions from this origin are not allowed.")

    client_key = request.client.host if request.client else "unknown"
    allowed, retry_after = community_reports.allow_submission(client_key)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Report submission rate limit reached. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    reporter_ref, token, _is_new = community_reports.ensure_reporter(request)
    _set_reporter_cookie(response, token)
    try:
        return community_reports.submit_report(
            report.url,
            report.category,
            report.evidence,
            reporter_ref,
        )
    except community_reports.DuplicateReportError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/api/community-reports/admin")
def get_admin_community_reports(
    request: Request,
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
):
    _require_report_admin(request)
    try:
        return {
            "reports": community_reports.list_admin_reports(
                status=status,
                limit=limit,
            )
        }
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/community-reports/{report_id}/moderation")
def moderate_community_report(
    report_id: int,
    moderation: CommunityModerationRequest,
    request: Request,
):
    _require_report_admin(request)
    if report_id < 1:
        raise HTTPException(status_code=404, detail="Community report not found.")
    try:
        result = community_reports.moderate_report(
            report_id,
            moderation.status,
            moderation.note,
        )
    except community_reports.ModerationConflictError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if result is None:
        raise HTTPException(status_code=404, detail="Community report not found.")
    return result


@app.get("/api/certificate-monitoring")
def get_certificate_monitors():
    return {
        "domains": certificate_monitor.list_monitored_domains(),
        "interval_seconds": CERTIFICATE_MONITOR_INTERVAL_SECONDS,
    }


@app.post("/api/certificate-monitoring")
def add_certificate_monitor(request: CertificateMonitorRequest):
    try:
        return certificate_monitor.add_monitored_domain(request.domain)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/api/certificate-monitoring/alerts")
def get_certificate_monitor_alerts():
    return {"alerts": certificate_monitor.list_certificate_alerts()}


@app.post("/api/certificate-monitoring/{domain_id}/check")
def check_certificate_monitor(domain_id: int):
    observation = certificate_monitor.check_domain(domain_id)
    if observation is None:
        raise HTTPException(status_code=404, detail="Monitored domain not found.")
    return observation


@app.get("/api/certificate-monitoring/{domain_id}/history")
def get_certificate_monitor_history(domain_id: int):
    history = certificate_monitor.get_domain_history(domain_id)
    if history is None:
        raise HTTPException(status_code=404, detail="Monitored domain not found.")
    return history


@app.delete("/api/certificate-monitoring/{domain_id}")
def remove_certificate_monitor(domain_id: int):
    if not certificate_monitor.remove_monitored_domain(domain_id):
        raise HTTPException(status_code=404, detail="Monitored domain not found.")
    return {"removed": True}


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
