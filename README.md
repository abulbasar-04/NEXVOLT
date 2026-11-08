# CYBERNOVA

CYBERNOVA is a cybersecurity intelligence demo for assessing suspicious URLs. It combines a trained phishing classifier, URL heuristics, third-party and community threat reports, TLS certificate inspection, and passive website checks into an explainable risk score and printable report.

## Problem and scope

People often need to decide whether a link merits closer inspection before opening it. CYBERNOVA gathers several independent signals and explains what was and was not assessed. Its results are triage assistance, not a guarantee of safety, a malware sandbox, or a substitute for security review.

## Architecture

| Area | Technology | Responsibility |
|---|---|---|
| Frontend | React, Vite, JavaScript, CSS | Responsive dashboard, scanner, history, intelligence pages, monitoring, reports |
| API | Python, FastAPI, Pydantic | Scan orchestration, validation, health, DNS, community report and certificate-monitoring endpoints |
| Analysis | scikit-learn, Python security services | Model inference, URL rules, threat-feed aggregation, certificate and passive website assessment, risk scoring |
| Persistence | SQLite | Community reports and certificate observations; scan history is stored in browser local storage |

The scan pipeline runs analysis components independently. The risk engine combines available, valid component scores and normalizes their weights; unavailable components are not treated as safe. Certificate change monitoring is historical and is not included in per-scan risk scoring.

## Features

- Unified risk score, category, derived trust score, component coverage, findings, and recommendations.
- Trained-model phishing probability and URL rule-based findings.
- URLhaus, PhishTank, and OpenPhish lookups where configured and reachable, plus conservative community-report signals.
- TLS certificate validity, hostname and chain checks, protocol/cipher assessment, and supported trust lookups.
- Passive HTTP security-header, redirect, cookie, HTTPS-enforcement, and bounded static mixed-content checks.
- Certificate fingerprint baselines, change history, alerts, and scheduled checks.
- Anonymous/pseudonymous community reports with public privacy filtering and optional administrator moderation.
- Per-scan security report with browser Print / Save as PDF.
- Browser-local scan history and responsive navigation.

External feeds and network checks can be unavailable or time out. A source no-match is not proof of safety. Community submissions are not independently verified identities.

## Requirements

- Python 3.9 or later (the current backend environment is Python 3.9).
- Node.js and npm.
- Network access for live website, DNS, certificate, and configured threat-feed checks. Unit tests mock external services and do not require live malicious URLs.
- Docker is not required.

## Setup

From the repository root:

```sh
python3 -m venv backend/venv
source backend/venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt
python -m pip install -r backend/requirements-dev.txt
cp backend/.env.example backend/.env
```

Edit `backend/.env` only if you need optional feed credentials or non-default settings. Do not commit `.env` or paste credentials into source code. Defaults use SQLite files under `backend/data/`.

Install frontend dependencies:

```sh
cd frontend
npm ci
cd ..
```

## Configuration and environment variables

`backend/intelligence/threat_intelligence.py` loads `backend/.env`; environment variables exported by the shell can also configure the backend. The Vite API URL is a frontend build-time setting.

| Variable | Required | Default / behavior |
|---|---:|---|
| `URLHAUS_AUTH_KEY` | No | URLhaus source is unavailable when unset; obtain a key from the provider if you want this lookup enabled. |
| `PHISHTANK_API_KEY` | No | PhishTank source is unavailable when unset; obtain an API key from the provider to enable it. |
| `OPENPHISH_FEED_URL` | No | `https://openphish.com/feed.txt`; use the official HTTPS feed unless you intentionally operate a trusted alternative. |
| `COMMUNITY_REPORT_ADMIN_TOKEN` | No | Moderation is disabled unless set to a high-entropy ASCII token (32–256 characters). Keep it secret. |
| `COMMUNITY_REPORT_COOKIE_SECURE` | No | Defaults to `false` for local HTTP; set to `true` when the API is served over HTTPS. |
| `COMMUNITY_REPORT_DATABASE` | No | `backend/data/community_reports.sqlite3`. |
| `CERTIFICATE_MONITOR_DATABASE` | No | `backend/data/certificate_monitoring.sqlite3`. |
| `CERTIFICATE_MONITOR_INTERVAL_SECONDS` | No | `21600` (6 hours), bounded by the service between 5 minutes and 30 days. |
| `VITE_API_BASE_URL` | No | `http://127.0.0.1:8000`; set before `npm run dev` if the API is elsewhere. |

Never put backend credentials in `VITE_*` variables: Vite values are shipped to the browser. The example environment file contains no credentials.

## Start the application

Run the API from the repository root:

```sh
source backend/venv/bin/activate
uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000
```

In another terminal, start the frontend:

```sh
cd frontend
npm run dev
```

Open `http://localhost:5173`. The API health check and interactive API docs are at `http://127.0.0.1:8000/api/health` and `http://127.0.0.1:8000/docs`. The browser only accepts a backend that identifies itself as CYBERNOVA; if an older server is occupying port 8000, stop that server and start this checkout's API.

To use a different local API port:

```sh
VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev
```

The development CORS allowlist is limited to `localhost:5173` and `127.0.0.1:5173`. Review and configure origins, HTTPS, authentication, rate limiting, and deployment secrets before exposing the API beyond a local demo.

## Test and build

From the repository root:

```sh
source backend/venv/bin/activate
PYTHONPATH=backend python -m pytest -q tests
python -m compileall -q backend tests
git diff --check
```

Build the frontend:

```sh
cd frontend
npm run build
```

The backend tests mock external intelligence and network responses; they should not scan real malicious URLs.

## Demo workflow

1. Start the API and frontend using the commands above. Confirm the sidebar reports the CYBERNOVA API as connected.
2. Open **URL scanner** and submit `https://example.com/`, a harmless example domain. The scan performs live passive checks and uses whatever threat feeds are configured; availability and results may vary with network access.
3. Review the risk score, the per-component availability, source results, certificate and website findings. Emphasize that a low score or no threat-feed match is not a safety guarantee.
4. Open **Trust dashboard**, then **Security report**. Use **Print / Save as PDF** to demonstrate browser-based report export.
5. Open **Certificate monitoring** and add `example.com` only if you want to demonstrate a real certificate baseline. This makes an outbound TLS connection and stores an observation in the configured SQLite database; remove the monitor after the demo if appropriate.
6. Optionally submit a community-demo report for `https://example.org/cybernova-demo-review` using category `other` and evidence such as “Harmless demo submission; no allegation of malicious activity.” This stores a local unverified community report; do not describe the example URL as malicious. Moderation is available only if an administrator token was configured privately.

For a fully deterministic presentation, use mocked responses in the existing tests rather than claiming that a live provider will return a particular result. Do not use real credentials, session links, customer URLs, or malicious URLs in the demo.

## Known limitations and safety

- CYBERNOVA is a local, single-user hackathon application, not a production multi-tenant service. Scan and certificate-monitoring endpoints do not implement user authentication. Bind the backend to loopback for a local demo; do not expose it publicly without adding appropriate authentication and abuse controls.
- Community moderation uses a shared bearer token, not individual administrator accounts. Report submission rate limiting is in-memory and per process, so it is not a distributed abuse-control mechanism.
- SQLite is suitable for the local demo. The certificate scheduler runs inside the API process; use one worker per shared monitoring database to avoid duplicate scheduled checks. SQLite lock timeouts do not replace a production database or distributed scheduler.
- Website assessment is passive: it does not execute JavaScript, authenticate, submit forms, or inspect beyond the configured response sample. DNS resolver-level timeouts depend on the host operating system.
- Threat providers have independent availability and credentials. Missing configuration, timeouts, and no-match responses must be shown as unavailable or source-specific no-match, not as proof of safety. The platform does not provide complete certificate-transparency, revocation, or global CA-distrust coverage.
- Scan URLs, including their query strings, may be sent to configured third-party intelligence providers and are saved in this browser's local history. Do not submit URLs containing credentials, session tokens, personal information, or other confidential data. The printable report omits URL query strings and excludes reporter identity and private community evidence.
- HTTPS alone does not establish that a site is legitimate. Automated risk and trust scores are evidence summaries, not guarantees that a website is safe or malicious.
