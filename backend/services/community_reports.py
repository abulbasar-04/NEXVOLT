
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import psycopg
from psycopg.rows import dict_row


REPORT_CATEGORIES = {
    "phishing", "malware", "scam", "impersonation",
    "suspicious redirect", "other",
}
REPORT_STATUSES = {"pending", "approved", "rejected", "resolved"}

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_rate_limit_lock = threading.Lock()
_submission_attempts = {}

RATE_LIMIT_MAX_SUBMISSIONS = 5
RATE_LIMIT_WINDOW_SECONDS = 60 * 60
MAX_RATE_LIMIT_CLIENTS = 2048
REPORTER_COOKIE_NAME = "cybernova_reporter"


class DuplicateReportError(ValueError):
    pass


class ModerationConflictError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_report_url(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError("Enter a URL no longer than 2048 characters.")

    if any(ord(character) < 0x20 for character in value):
        raise ValueError("URL contains invalid control characters.")

    try:
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from error

    if scheme not in ("http", "https") or not hostname:
        raise ValueError("Only absolute HTTP and HTTPS URLs can be reported.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials cannot be reported.")

    try:
        host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("URL contains an invalid domain name.") from error

    if not host or len(host) > 253:
        raise ValueError("URL contains an invalid domain name.")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            len(labels) < 2
            or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
            or host == "localhost"
            or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa"))
        ):
            raise ValueError("Private, local, or invalid hostnames cannot be reported.")
    else:
        if not address.is_global:
            raise ValueError("Private or non-public IP addresses cannot be reported.")

    netloc_host = f"[{host}]" if ":" in host else host

    if port and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        netloc = f"{netloc_host}:{port}"
    else:
        netloc = netloc_host

    normalized_url = urlunsplit(
        (scheme, netloc, parsed.path or "/", parsed.query, "")
    )
    return normalized_url, host


def _connect():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured.")

    return psycopg.connect(database_url, row_factory=dict_row)


@contextmanager
def _database():
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _reporter_secret(connection) -> bytes:
    row = connection.execute(
        """
        SELECT value
        FROM community_report_metadata
        WHERE key = 'reporter_signing_secret'
        """
    ).fetchone()

    if row is None:
        raise RuntimeError("Community reporter signing secret is unavailable.")

    return bytes.fromhex(row["value"])


def _sign_reporter_id(reporter_id: str, secret: bytes) -> str:
    signature = hmac.new(
        secret, reporter_id.encode("ascii"), hashlib.sha256
    ).hexdigest()
    return f"{reporter_id}.{signature}"


def _reporter_reference(token: str | None, secret: bytes) -> tuple[str, str]:
    if isinstance(token, str) and len(token) <= 180:
        reporter_id, separator, supplied_signature = token.partition(".")

        if separator and re.fullmatch(r"[A-Za-z0-9_-]{20,100}", reporter_id):
            expected_token = _sign_reporter_id(reporter_id, secret)
            expected_signature = expected_token.partition(".")[2]

            if hmac.compare_digest(supplied_signature, expected_signature):
                reference = hmac.new(
                    secret,
                    f"reference:{reporter_id}".encode("ascii"),
                    hashlib.sha256,
                ).hexdigest()
                return reference, token

    reporter_id = secrets.token_urlsafe(32)
    token = _sign_reporter_id(reporter_id, secret)

    reference = hmac.new(
        secret,
        f"reference:{reporter_id}".encode("ascii"),
        hashlib.sha256,
    ).hexdigest()

    return reference, token


def ensure_reporter(request):
    token = request.cookies.get(REPORTER_COOKIE_NAME)

    with _database() as connection:
        secret = _reporter_secret(connection)
        reference, signed_token = _reporter_reference(token, secret)

    return reference, signed_token, signed_token != token


def _public_report(row, include_query=False):
    normalized_url = row["normalized_url"]

    if not include_query:
        parsed = urlsplit(normalized_url)
        normalized_url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, "", "")
        )

    return {
        "id": row["id"],
        "url": normalized_url,
        "domain": row["normalized_domain"],
        "category": row["category"],
        "submitted_at": row["submitted_at"],
        "status": row["moderation_status"],
        "report_count": row["report_count"],
        "distinct_reporters": row["distinct_reporters"],
    }


def _clean_evidence(value: str | None) -> str:
    if value is None:
        return ""

    if not isinstance(value, str) or len(value) > 2000:
        raise ValueError("Evidence must be 2000 characters or fewer.")

    cleaned = _CONTROL_CHARS.sub("", value).strip()

    if len(cleaned) > 2000:
        raise ValueError("Evidence must be 2000 characters or fewer.")

    return cleaned


def submit_report(
    url: str,
    category: str,
    evidence: str | None,
    reporter_ref: str,
):
    normalized_url, domain = normalize_report_url(url)
    normalized_category = " ".join(
        str(category or "").strip().lower().split()
    )

    if normalized_category not in REPORT_CATEGORIES:
        raise ValueError("Select a supported report category.")

    cleaned_evidence = _clean_evidence(evidence)
    submitted_at = _now()

    try:
        with _database() as connection:
            row = connection.execute(
                """
                INSERT INTO community_reports (
                    normalized_url, normalized_domain, category,
                    evidence, reporter_ref, submitted_at
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    normalized_url,
                    domain,
                    normalized_category,
                    cleaned_evidence,
                    reporter_ref,
                    submitted_at,
                ),
            ).fetchone()

            return {
                "id": row["id"],
                "url": normalized_url,
                "domain": domain,
                "category": normalized_category,
                "submitted_at": submitted_at,
                "status": "pending",
                "message": (
                    "Report submitted for review. "
                    "A report is not a confirmed threat."
                ),
            }

    except psycopg.errors.UniqueViolation as error:
        raise DuplicateReportError(
            "This browser has already submitted a report for this URL."
        ) from error


def list_public_reports(limit: int = 50, offset: int = 0):
    with _database() as connection:
        rows = connection.execute(
            """
            SELECT report.id, report.normalized_url,
                   report.normalized_domain, report.category,
                   report.submitted_at, report.moderation_status,
                   (
                       SELECT COUNT(*) FROM community_reports AS active
                       WHERE active.normalized_url = report.normalized_url
                         AND active.moderation_status != 'rejected'
                   ) AS report_count,
                   (
                       SELECT COUNT(DISTINCT active.reporter_ref)
                       FROM community_reports AS active
                       WHERE active.normalized_url = report.normalized_url
                         AND active.moderation_status != 'rejected'
                   ) AS distinct_reporters
            FROM community_reports AS report
            WHERE report.moderation_status != 'rejected'
            ORDER BY report.submitted_at DESC, report.id DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        ).fetchall()

        return [_public_report(row) for row in rows]


def list_verified_reports(limit: int = 50, offset: int = 0):
    with _database() as connection:
        rows = connection.execute(
            """
            SELECT report.id, report.normalized_url,
                   report.normalized_domain, report.category,
                   report.submitted_at, report.moderation_status,
                   (
                       SELECT COUNT(*) FROM community_reports AS verified
                       WHERE verified.normalized_url = report.normalized_url
                         AND verified.moderation_status = 'approved'
                   ) AS report_count,
                   (
                       SELECT COUNT(DISTINCT verified.reporter_ref)
                       FROM community_reports AS verified
                       WHERE verified.normalized_url = report.normalized_url
                         AND verified.moderation_status = 'approved'
                   ) AS distinct_reporters
            FROM community_reports AS report
            WHERE report.moderation_status = 'approved'
            ORDER BY report.submitted_at DESC, report.id DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        ).fetchall()

        return [_public_report(row) for row in rows]


def list_admin_reports(status: str | None = None, limit: int = 100):
    if status is not None and status not in REPORT_STATUSES:
        raise ValueError("Select a valid moderation status.")

    with _database() as connection:
        query = """
            SELECT report.*,
                   (
                       SELECT COUNT(*) FROM community_reports AS related
                       WHERE related.normalized_url = report.normalized_url
                         AND related.moderation_status != 'rejected'
                   ) AS report_count,
                   (
                       SELECT COUNT(DISTINCT related.reporter_ref)
                       FROM community_reports AS related
                       WHERE related.normalized_url = report.normalized_url
                         AND related.moderation_status != 'rejected'
                   ) AS distinct_reporters
            FROM community_reports AS report
        """

        if status:
            rows = connection.execute(
                query + """
                    WHERE report.moderation_status = %s
                    ORDER BY report.submitted_at DESC, report.id DESC
                    LIMIT %s
                """,
                (status, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                query + """
                    ORDER BY report.submitted_at DESC, report.id DESC
                    LIMIT %s
                """,
                (limit,),
            ).fetchall()

        return [
            {
                **_public_report(row, include_query=True),
                "evidence": row["evidence"],
                "moderation_note": row["moderation_note"],
            }
            for row in rows
        ]


def moderate_report(
    report_id: int,
    new_status: str,
    note: str | None = None,
):
    if new_status not in {"approved", "rejected", "resolved"}:
        raise ValueError("Select approved, rejected, or resolved.")

    clean_note = _clean_evidence(note)

    with _database() as connection:
        row = connection.execute(
            """
            SELECT moderation_status
            FROM community_reports
            WHERE id = %s
            FOR UPDATE
            """,
            (report_id,),
        ).fetchone()

        if row is None:
            return None

        old_status = row["moderation_status"]

        allowed_transitions = {
            "pending": {"approved", "rejected", "resolved"},
            "approved": {"resolved"},
        }

        if new_status not in allowed_transitions.get(old_status, set()):
            raise ModerationConflictError(
                f"Cannot change a {old_status} report to {new_status}."
            )

        changed_at = _now()

        connection.execute(
            """
            UPDATE community_reports
            SET moderation_status = %s,
                moderated_at = %s,
                moderation_note = %s
            WHERE id = %s
            """,
            (new_status, changed_at, clean_note, report_id),
        )

        connection.execute(
            """
            INSERT INTO community_report_moderation (
                report_id, previous_status, new_status, note, changed_at
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (report_id, old_status, new_status, clean_note, changed_at),
        )

        return {
            "id": report_id,
            "status": new_status,
            "moderated_at": changed_at,
        }


def lookup_community_reports(url: str):
    normalized_url, domain = normalize_report_url(url)

    with _database() as connection:
        rows = connection.execute(
            """
            SELECT category, moderation_status, reporter_ref, submitted_at
            FROM community_reports
            WHERE (normalized_url = %s OR normalized_domain = %s)
              AND moderation_status IN ('pending', 'approved')
            """,
            (normalized_url, domain),
        ).fetchall()

    reporters = {row["reporter_ref"] for row in rows}
    reviewed_reporters = {
        row["reporter_ref"]
        for row in rows
        if row["moderation_status"] == "approved"
    }

    categories = {}
    for row in rows:
        categories[row["category"]] = categories.get(row["category"], 0) + 1

    if rows:
        status = "reviewed" if reviewed_reporters else "unverified"
        checked_at = _now()
        reported_at = max(row["submitted_at"] for row in rows)
        confidence = "medium" if len(reporters) >= 2 else "low"
    else:
        status = "not_found"
        checked_at = _now()
        reported_at = None
        confidence = None

    return {
        "source": "Community reports",
        "queried_url": normalized_url,
        "status": status,
        "malicious": False,
        "category": None,
        "confidence": confidence,
        "confidence_note": (
            "Community reports are user-submitted and are not proof of malicious activity."
            if rows else None
        ),
        "checked_at": checked_at,
        "reported_at": reported_at,
        "details": {
            "report_count": len(rows),
            "distinct_reporters": len(reporters),
            "reviewed_reporters": len(reviewed_reporters),
            "categories": categories,
        },
        "error": None,
    }


def allow_submission(
    client_key: str,
    now: float | None = None,
) -> tuple[bool, int]:
    current_time = time.monotonic() if now is None else now

    with _rate_limit_lock:
        attempts = _submission_attempts.setdefault(client_key, [])

        attempts[:] = [
            timestamp for timestamp in attempts
            if current_time - timestamp < RATE_LIMIT_WINDOW_SECONDS
        ]

        if len(attempts) >= RATE_LIMIT_MAX_SUBMISSIONS:
            retry_after = max(
                1,
                int(RATE_LIMIT_WINDOW_SECONDS - (current_time - attempts[0])),
            )
            return False, retry_after

        if len(_submission_attempts) > MAX_RATE_LIMIT_CLIENTS:
            stale_cutoff = current_time - RATE_LIMIT_WINDOW_SECONDS

            for key in list(_submission_attempts):
                _submission_attempts[key] = [
                    timestamp for timestamp in _submission_attempts[key]
                    if timestamp >= stale_cutoff
                ]

                if not _submission_attempts[key]:
                    del _submission_attempts[key]

        attempts.append(current_time)
        return True, 0
