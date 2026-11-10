
import json
import logging
import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row

from intelligence.certificate_analyzer import analyze_certificate

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
MAX_MONITORED_DOMAINS = 100
_check_lock = threading.RLock()

RECOMMENDATIONS = {
    "renewal": (
        "Confirm this renewal was expected and that automated certificate "
        "deployment completed successfully."
    ),
    "potentially_suspicious": (
        "Verify the issuer and certificate details with the domain owner through "
        "a trusted channel. A change alone does not establish malicious activity."
    ),
    "unavailable": (
        "Retry the check later and confirm the domain is reachable over HTTPS."
    ),
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a domain to monitor.")

    candidate = value.strip()

    if (
        "://" in candidate
        or any(character in candidate for character in "/\\@:#?")
        or candidate.endswith(".")
    ):
        raise ValueError("Enter a domain name only, without a URL, port, or path.")

    try:
        domain = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Enter a valid internationalized domain name.") from error

    if len(domain) > 253:
        raise ValueError("Domain name is too long.")

    labels = domain.split(".")
    if len(labels) < 2 or any(
        not _DOMAIN_LABEL.fullmatch(label) for label in labels
    ):
        raise ValueError("Enter a fully qualified domain name.")

    return domain


def _connect():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured.")

    return psycopg.connect(
        DATABASE_URL,
        connect_timeout=15,
        row_factory=dict_row,
    )


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


def _json_value(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"))
        if value is not None
        else None
    )


def _decode_json(value, fallback=None):
    if value is None:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        logger.warning("Stored certificate monitoring data contains invalid JSON.")
        return fallback


def _observation(row):
    if row is None:
        return None

    return {
        "id": row["id"],
        "domain_id": row["domain_id"],
        "observed_at": row["observed_at"].isoformat()
        if isinstance(row["observed_at"], datetime)
        else row["observed_at"],
        "status": row["status"],
        "sha256_fingerprint": row["fingerprint"],
        "issuer": _decode_json(row["issuer_json"]),
        "subject": _decode_json(row["subject_json"]),
        "serial_number": row["serial_number"],
        "public_key": _decode_json(row["public_key_json"]),
        "not_before": row["not_before"],
        "expires_at": row["expires_at"],
        "san_domains": _decode_json(row["san_domains_json"], []),
        "change_type": row["change_type"],
        "severity": row["severity"],
        "evidence": _decode_json(row["evidence_json"], []),
        "recommendation": row["recommendation"],
    }


def _latest_observation(connection, domain_id):
    row = connection.execute(
        """
        SELECT *
        FROM certificate_observations
        WHERE domain_id = %s
        ORDER BY id DESC
        LIMIT 1
        """,
        (domain_id,),
    ).fetchone()

    return _observation(row)


def _domain_record(connection, row):
    return {
        "id": row["id"],
        "domain": row["domain"],
        "created_at": row["created_at"].isoformat()
        if isinstance(row["created_at"], datetime)
        else row["created_at"],
        "last_checked_at": row["last_checked_at"].isoformat()
        if isinstance(row["last_checked_at"], datetime)
        else row["last_checked_at"],
        "latest_status": row.get("latest_status") or "pending",
        "latest_observation": _latest_observation(connection, row["id"]),
    }


def list_monitored_domains():
    with _database() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM monitored_domains
            WHERE enabled = TRUE
            ORDER BY domain
            """
        ).fetchall()

        return [_domain_record(connection, row) for row in rows]


def get_monitored_domain(domain_id: int):
    with _database() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM monitored_domains
            WHERE id = %s AND enabled = TRUE
            """,
            (domain_id,),
        ).fetchone()

        return _domain_record(connection, row) if row else None


def _sanitize_certificate(analysis: dict) -> dict:
    fingerprint = analysis.get("sha256_fingerprint")

    if isinstance(fingerprint, str):
        fingerprint = fingerprint.lower().replace(":", "").strip()
        if not _FINGERPRINT.fullmatch(fingerprint):
            fingerprint = None
    else:
        fingerprint = None

    sans = analysis.get("subject_alt_names")
    if not isinstance(sans, list):
        sans = []

    return {
        "status": str(analysis.get("status") or "unknown"),
        "fingerprint": fingerprint,
        "issuer": analysis.get("issuer"),
        "subject": analysis.get("subject"),
        "serial_number": analysis.get("serial_number"),
        "public_key": analysis.get("public_key"),
        "not_before": analysis.get("not_before"),
        "expires_at": analysis.get("expires_at"),
        "san_domains": sans,
    }


def _san_set(values):
    normalized = set()

    for item in values or []:
        value = item.get("value") if isinstance(item, dict) else item
        if isinstance(value, str) and value:
            normalized.add(value.rstrip(".").casefold())

    return normalized


def _date(value):
    if not isinstance(value, str) or not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _classify_change(previous: dict, current: dict):
    evidence = [
        "SHA-256 certificate fingerprint changed.",
        f"Previous fingerprint: {previous['fingerprint']}.",
        f"Current fingerprint: {current['fingerprint']}.",
    ]

    issuer_changed = previous["issuer"] != current["issuer"]
    previous_sans = _san_set(previous["san_domains"])
    current_sans = _san_set(current["san_domains"])
    sans_changed = previous_sans != current_sans

    previous_key = previous.get("public_key") or {}
    current_key = current.get("public_key") or {}
    previous_key_fp = previous_key.get("sha256_fingerprint")
    current_key_fp = current_key.get("sha256_fingerprint")

    key_changed = (
        previous_key_fp != current_key_fp
        if previous_key_fp and current_key_fp
        else (
            previous_key.get("algorithm"),
            previous_key.get("key_size"),
        )
        != (
            current_key.get("algorithm"),
            current_key.get("key_size"),
        )
    )

    old_expiry = _date(previous.get("expires_at"))
    new_expiry = _date(current.get("expires_at"))
    new_start = _date(current.get("not_before"))

    validity_gap = bool(old_expiry and new_start and new_start > old_expiry)
    future_validity_start = bool(
        new_start and new_start > datetime.now(timezone.utc) + timedelta(days=7)
    )

    renewed = (
        not issuer_changed
        and not sans_changed
        and not validity_gap
        and not future_validity_start
        and old_expiry is not None
        and new_expiry is not None
        and new_expiry > old_expiry
        and current["status"] == "valid"
    )

    if issuer_changed:
        evidence.append(
            "Certificate issuer changed from "
            f"{json.dumps(previous['issuer'], sort_keys=True)} to "
            f"{json.dumps(current['issuer'], sort_keys=True)}."
        )

    if sans_changed:
        removed_sans = sorted(previous_sans - current_sans)
        added_sans = sorted(current_sans - previous_sans)

        if removed_sans:
            evidence.append(f"Removed SAN entries: {', '.join(removed_sans)}.")
        if added_sans:
            evidence.append(f"Added SAN entries: {', '.join(added_sans)}.")

    if key_changed:
        evidence.append("Certificate public key changed.")

    if previous.get("serial_number") != current.get("serial_number"):
        evidence.append("Certificate serial number changed.")

    if validity_gap:
        evidence.append(
            "The new certificate validity starts after the previous certificate expired."
        )

    if future_validity_start:
        evidence.append(
            "The new certificate validity starts more than seven days in the future."
        )

    if (
        previous.get("not_before") != current.get("not_before")
        or previous.get("expires_at") != current.get("expires_at")
    ):
        evidence.append(
            "Validity dates changed from "
            f"{previous.get('not_before') or 'unknown'} to "
            f"{previous.get('expires_at') or 'unknown'} "
            "and "
            f"{current.get('not_before') or 'unknown'} to "
            f"{current.get('expires_at') or 'unknown'}."
        )

    if current["status"] != "valid":
        evidence.append(
            "The new certificate did not pass analyzer validation "
            f"(status: {current['status']})."
        )

    if not renewed and not any(
        (issuer_changed, sans_changed, key_changed, validity_gap)
    ):
        evidence.append(
            "The change does not match the available normal-renewal indicators."
        )

    if renewed:
        return "renewal", "low", evidence

    severity = "high" if current["status"] in ("expired", "invalid") else "medium"
    return "potentially_suspicious", severity, evidence


def check_domain(domain_id: int):
    with _check_lock:
        with _database() as connection:
            domain_row = connection.execute(
                """
                SELECT *
                FROM monitored_domains
                WHERE id = %s AND enabled = TRUE
                """,
                (domain_id,),
            ).fetchone()

            if not domain_row:
                return None

            domain = domain_row["domain"]

            previous_row = connection.execute(
                """
                SELECT *
                FROM certificate_observations
                WHERE domain_id = %s AND fingerprint IS NOT NULL
                ORDER BY id DESC
                LIMIT 1
                """,
                (domain_id,),
            ).fetchone()

            previous = _observation(previous_row)

        try:
            raw_analysis = analyze_certificate(
                f"https://{domain}/",
                include_transparency=False,
            )
            analysis = raw_analysis if isinstance(raw_analysis, dict) else {}
        except Exception:
            logger.exception("Certificate monitor check failed for %s.", domain)
            analysis = {"status": "unavailable", "error": "TLS analysis failed."}

        certificate = _sanitize_certificate(analysis)
        observed_at = _now()
        evidence = []
        change_type = "unavailable"
        severity = None
        recommendation = RECOMMENDATIONS["unavailable"]

        if certificate["fingerprint"]:
            if previous is None:
                change_type = "baseline"
                evidence = ["First certificate observation; baseline created."]
                recommendation = None

            elif certificate["fingerprint"] == previous["sha256_fingerprint"]:
                change_type = "unchanged"
                evidence = [
                    "SHA-256 certificate fingerprint matches the prior observation."
                ]
                recommendation = None

            else:
                prior = {
                    "fingerprint": previous["sha256_fingerprint"],
                    "issuer": previous["issuer"],
                    "subject": previous["subject"],
                    "public_key": previous["public_key"],
                    "serial_number": previous["serial_number"],
                    "not_before": previous["not_before"],
                    "expires_at": previous["expires_at"],
                    "san_domains": previous["san_domains"],
                }

                change_type, severity, evidence = _classify_change(prior, certificate)
                recommendation = RECOMMENDATIONS[change_type]

        elif analysis.get("error"):
            evidence = [str(analysis["error"])]
        else:
            evidence = ["No certificate fingerprint was available from this check."]

        with _database() as connection:
            row = connection.execute(
                """
                INSERT INTO certificate_observations (
                    domain_id, observed_at, status, fingerprint, issuer_json,
                    subject_json, serial_number, public_key_json, not_before,
                    expires_at, san_domains_json, change_type, severity,
                    evidence_json, recommendation
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                RETURNING *
                """,
                (
                    domain_id,
                    observed_at,
                    certificate["status"],
                    certificate["fingerprint"],
                    _json_value(certificate["issuer"]),
                    _json_value(certificate["subject"]),
                    str(certificate["serial_number"])
                    if certificate["serial_number"] is not None
                    else None,
                    _json_value(certificate["public_key"]),
                    certificate["not_before"],
                    certificate["expires_at"],
                    _json_value(certificate["san_domains"]),
                    change_type,
                    severity,
                    _json_value(evidence),
                    recommendation,
                ),
            ).fetchone()

            connection.execute(
                """
                UPDATE monitored_domains
                SET last_checked_at = %s,
                    latest_status = %s,
                    last_status = %s,
                    last_fingerprint = %s,
                    last_expires_at = %s
                WHERE id = %s
                """,
                (
                    observed_at,
                    certificate["status"],
                    certificate["status"],
                    certificate["fingerprint"],
                    certificate["expires_at"],
                    domain_id,
                ),
            )

            return _observation(row)


def add_monitored_domain(value: str):
    domain = normalize_domain(value)

    with _check_lock:
        with _database() as connection:
            existing = connection.execute(
                "SELECT * FROM monitored_domains WHERE domain = %s",
                (domain,),
            ).fetchone()

            if existing and existing["enabled"]:
                return {
                    "created": False,
                    "domain": _domain_record(connection, existing),
                }

            active_count = connection.execute(
                "SELECT COUNT(*) AS count FROM monitored_domains WHERE enabled = TRUE"
            ).fetchone()["count"]

            if active_count >= MAX_MONITORED_DOMAINS:
                raise ValueError(
                    f"At most {MAX_MONITORED_DOMAINS} domains can be monitored."
                )

            if existing:
                connection.execute(
                    "UPDATE monitored_domains SET enabled = TRUE WHERE id = %s",
                    (existing["id"],),
                )
                domain_id = existing["id"]
                created = False

            else:
                row = connection.execute(
                    """
                    INSERT INTO monitored_domains (domain, created_at)
                    VALUES (%s, %s)
                    RETURNING id
                    """,
                    (domain, _now()),
                ).fetchone()

                domain_id = row["id"]
                created = True

    observation = check_domain(domain_id)

    return {
        "created": created,
        "domain": get_monitored_domain(domain_id),
        "observation": observation,
    }


def remove_monitored_domain(domain_id: int) -> bool:
    with _database() as connection:
        cursor = connection.execute(
            """
            UPDATE monitored_domains
            SET enabled = FALSE
            WHERE id = %s AND enabled = TRUE
            """,
            (domain_id,),
        )
        return cursor.rowcount > 0


def get_domain_history(domain_id: int):
    with _database() as connection:
        domain = connection.execute(
            """
            SELECT *
            FROM monitored_domains
            WHERE id = %s AND enabled = TRUE
            """,
            (domain_id,),
        ).fetchone()

        if not domain:
            return None

        rows = connection.execute(
            """
            SELECT *
            FROM certificate_observations
            WHERE domain_id = %s
            ORDER BY id DESC
            LIMIT 100
            """,
            (domain_id,),
        ).fetchall()

        return {
            "domain": domain["domain"],
            "observations": [_observation(row) for row in rows],
        }


def list_certificate_alerts(limit: int = 100):
    bounded_limit = max(1, min(int(limit), 500))

    with _database() as connection:
        rows = connection.execute(
            """
            SELECT observations.*, domains.domain
            FROM certificate_observations AS observations
            JOIN monitored_domains AS domains
                ON domains.id = observations.domain_id
            WHERE domains.enabled = TRUE
                AND observations.change_type IN (
                    'renewal', 'potentially_suspicious'
                )
            ORDER BY observations.id DESC
            LIMIT %s
            """,
            (bounded_limit,),
        ).fetchall()

        alerts = []

        for row in rows:
            alert = _observation(row)
            alert["domain"] = row["domain"]
            alert["detected_at"] = alert["observed_at"]
            alerts.append(alert)

        return alerts


def monitored_domain_ids():
    with _database() as connection:
        rows = connection.execute(
            """
            SELECT id
            FROM monitored_domains
            WHERE enabled = TRUE
            ORDER BY id
            """
        ).fetchall()

        return [row["id"] for row in rows]


def check_all_monitored_domains():
    results = []

    for domain_id in monitored_domain_ids():
        result = check_domain(domain_id)
        if result is not None:
            results.append(result)

    return results
