import React, { useEffect, useMemo, useRef, useState } from "react";
import { API_BASE_URL, getHealth, lookupDns, scanUrl } from "./api.js";
import Icon from "./components/Icon.jsx";
import Sidebar from "./components/Sidebar.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import ScannerPage from "./pages/ScannerPage.jsx";
import ScanHistoryPage from "./pages/ScanHistoryPage.jsx";
import ThreatIntelligencePage from "./pages/ThreatIntelligencePage.jsx";
import CommunityReportsPage from "./pages/CommunityReportsPage.jsx";
import SSLAnalysisPage from "./pages/SSLAnalysisPage.jsx";
import CertificateMonitoringPage from "./pages/CertificateMonitoringPage.jsx";
import TrustDashboard from "./pages/TrustDashboard.jsx";
import SecurityReportPage from "./pages/SecurityReportPage.jsx";
import {
  getCertificateDisplayStatus,
  isCertificateVerified,
} from "./utils/certificate.js";
import { hasUnifiedRiskScore } from "./utils/riskScore.js";

const HISTORY_KEY = "nexvolt.scan-history.v1";

function readHistory() {
  try {
    const stored = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(stored) ? stored : [];
  } catch (error) {
    console.warn("Could not read saved CYBERNOVA scan history.", error);
    return [];
  }
}

function normalizeUrl(value) {
  const trimmed = value.trim();
  if (!trimmed) throw new Error("Enter a website URL to scan.");
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("Enter a valid website URL.");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
    throw new Error("Only HTTP and HTTPS URLs can be scanned.");
  }
  return parsed.href;
}

function formatDate(value) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function getVerdictTone(verdict = "") {
  const normalized = verdict.toLowerCase();
  if (normalized.includes("danger") || normalized.includes("phish")) return "danger";
  if (normalized.includes("suspicious")) return "warning";
  return "safe";
}

function getScanStatus(result) {
  if (
    !hasUnifiedRiskScore(result) ||
    String(result.risk_category || "").toLowerCase() === "unknown" ||
    String(result.verdict || "").toLowerCase() === "unknown"
  ) {
    return { label: "Unknown", tone: "warning", heuristicRisk: false, modelRisk: false };
  }

  const heuristicRisk = getVerdictTone(result.verdict) !== "safe";
  const prediction = result.ml_prediction?.prediction || "";
  const phishingProbability = Number(result.ml_prediction?.phishing_probability);
  const legitimateProbability = Number(result.ml_prediction?.legitimate_probability);
  const modelHasPrediction = Boolean(prediction) || Number.isFinite(phishingProbability);
  const modelRisk = getVerdictTone(prediction) === "danger" ||
    (Number.isFinite(phishingProbability) && phishingProbability >= 50);

  if (modelHasPrediction && heuristicRisk !== modelRisk) {
    return { label: "Mixed signals", tone: "warning", heuristicRisk, modelRisk };
  }
  if (getVerdictTone(result.verdict) === "danger" || modelRisk) {
    return { label: prediction || result.verdict, tone: "danger", heuristicRisk, modelRisk };
  }
  if (heuristicRisk || (Number.isFinite(legitimateProbability) && legitimateProbability >= 50)) {
    return { label: result.verdict, tone: getVerdictTone(result.verdict), heuristicRisk, modelRisk };
  }
  return { label: result.verdict || prediction || "Unknown", tone: "safe", heuristicRisk, modelRisk };
}

function isRiskyScan(scan) {
  const status = getScanStatus(scan.result);
  return status.heuristicRisk || status.modelRisk;
}

function SidebarHeader({ title, subtitle, onMenu }) {
  return (
    <header className="topbar">
      <button className="icon-button mobile-menu" onClick={onMenu} aria-label="Open navigation">
        <Icon name="menu" />
      </button>
      <div className="page-heading"><h1>{title}</h1><p>{subtitle}</p></div>
      <div className="topbar-right">
        <span className="environment-pill"><span className="status-dot online" /> LIVE ENVIRONMENT</span>
        <div className="user-avatar" title="CYBERNOVA workspace"><img src="/cybernova-logo.png" alt="CYBERNOVA" /></div>
      </div>
    </header>
  );
}

function MetricCard({ label, value, caption, icon, tone = "purple" }) {
  return (
    <article className="metric-card">
      <div className={`metric-icon ${tone}`}><Icon name={icon} size={18} /></div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-caption">{caption}</div>
    </article>
  );
}

function ScanComposer({ value, onChange, onSubmit, scanning, error }) {
  return (
    <section className="scan-card">
      <div className="scan-card-top">
        <div>
          <div className="eyebrow"><span className="eyebrow-line" /> REAL-TIME URL ANALYSIS</div>
          <h2>Is this link safe?</h2>
          <p>Run a URL through our AI-powered phishing and risk analysis.</p>
        </div>
        <div className="scan-orb"><Icon name="target" size={24} /></div>
      </div>
      <form className="scan-form" onSubmit={onSubmit}>
        <Icon name="globe" size={19} className="input-icon" />
        <input
          type="text"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder="Paste a URL to inspect, e.g. https://example.com"
          aria-label="Website URL to scan"
          maxLength={2048}
          autoComplete="url"
          disabled={scanning}
        />
        {value && !scanning && (
          <button className="clear-input" type="button" onClick={() => onChange("")} aria-label="Clear URL">
            <Icon name="close" size={16} />
          </button>
        )}
        <button className="scan-button" type="submit" disabled={scanning}>
          {scanning ? <span className="spinner" /> : <Icon name="search" size={17} />}
          <span>{scanning ? "Analyzing" : "Scan URL"}</span>
          {!scanning && <span className="button-shortcut">↵</span>}
        </button>
      </form>
      {error && <div className="inline-error" role="alert"><Icon name="shieldAlert" size={16} />{error}</div>}
      <div className="scan-assurance">
        <span><Icon name="lock" size={13} /> Your scan stays private</span>
        <span className="assurance-divider" />
        <span>HTTP & HTTPS supported</span>
        <span className="assurance-divider" />
        <span>Usually takes a few seconds</span>
      </div>
    </section>
  );
}

function RiskScore({ score, verdict, tone: statusTone, label = "RISK SCORE" }) {
  const tone = statusTone || getVerdictTone(verdict);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const hasScore = score !== null && score !== undefined && Number.isFinite(Number(score));
  const numericScore = hasScore ? Number(score) : 0;
  const progress = circumference * (1 - Math.min(Math.max(numericScore, 0), 100) / 100);
  return (
    <div className={`risk-score ${tone}`}>
      <svg
        viewBox="0 0 128 128"
        className="risk-ring"
        role="img"
        aria-label={hasScore ? `${label} ${numericScore} out of 100` : `${label} unavailable`}
      >
        <circle className="risk-track" cx="64" cy="64" r={radius} />
        <circle
          className="risk-progress"
          cx="64"
          cy="64"
          r={radius}
          strokeDasharray={circumference}
          strokeDashoffset={progress}
        />
      </svg>
      <div className="risk-score-number"><strong>{hasScore ? numericScore : "—"}</strong><span>/100</span></div>
      <span className="risk-score-label">{label}</span>
    </div>
  );
}

function ScanResult({ scan, onViewReport }) {
  const result = scan.result;
  const status = getScanStatus(result);
  const tone = status.tone;
  const ml = result.ml_prediction || {};
  const analysis = result.analysis || {};
  const certificate = result.certificate_analysis || {};
  const certificateStatus = getCertificateDisplayStatus(certificate);
  const certificateVerified = isCertificateVerified(certificate);
  const website = result.website_analysis || {};
  const websiteFindings = Array.isArray(website.findings) ? website.findings : [];
  const websiteFindingTitles = new Set(websiteFindings);
  const scanFindings = (Array.isArray(result.findings) ? result.findings : []).filter(
    (finding) => !websiteFindingTitles.has(finding),
  );
  const websiteHeaders = Object.entries(website.security_headers || {});
  const checkedHeaders = websiteHeaders.filter(([, present]) => present !== null);
  const presentHeaderCount = checkedHeaders.filter(([, present]) => present === true).length;
  const observedCookies = Array.isArray(website.cookies) ? website.cookies : [];
  const redirectAnalysis = website.redirect_analysis;
  const mixedContent = website.mixed_content || {};
  const websiteFindingDetails = Array.isArray(result.finding_details)
    ? result.finding_details.filter((finding) => finding.source === "website_assessment")
    : [];
  const displayRedirectTarget = (value) => {
    try {
      const target = new URL(value);
      return `${target.host}${target.pathname}`;
    } catch {
      return "Unavailable destination";
    }
  };
  const scoreExplanation = result.score_explanation;
  const unifiedScoreAvailable = hasUnifiedRiskScore(result);
  const hasTrustScore = unifiedScoreAvailable && Number.isFinite(result.trust_score);
  const displayedScore = unifiedScoreAvailable
    ? hasTrustScore ? result.trust_score : result.risk_score
    : null;
  const dnsRecords = scan.dns?.dns_records || {};
  const recordCount = Object.values(dnsRecords).reduce(
    (count, records) => count + (Array.isArray(records) ? records.length : 0),
    0,
  );
  return (
    <section className="result-card" aria-live="polite">
      <div className="result-header">
        <div className="result-title-wrap">
          <div className={`result-status-icon ${tone}`}><Icon name={tone === "safe" ? "shield" : "shieldAlert"} size={20} /></div>
          <div><div className="section-kicker">LATEST ANALYSIS</div><h2>Scan result</h2></div>
        </div>
        {onViewReport && (
          <button type="button" className="text-button no-print" onClick={() => onViewReport(scan)}>
            Full report <Icon name="chevron" size={14} />
          </button>
        )}
        <span className="timestamp"><Icon name="clock" size={14} />{formatDate(scan.scannedAt)}</span>
      </div>
      <div className="result-main">
        <RiskScore
          score={displayedScore}
          verdict={unifiedScoreAvailable ? result.verdict : "Unknown"}
          tone={tone}
          label={hasTrustScore ? "WEBSITE TRUST" : "UNIFIED RISK SCORE"}
        />
        <div className="result-summary">
          <span className={`verdict-pill ${tone}`}><span className="status-dot" />{status.label}</span>
          {status.label === "Mixed signals" && <p className="status-conflict">Heuristics: {result.verdict} · AI model: {ml.prediction || "no classification"}</p>}
          <h3 className="scanned-domain">{analysis.domain || result.url}</h3>
          <a className="scanned-url" href={result.url} target="_blank" rel="noreferrer">
            {result.url}<Icon name="arrowUpRight" size={13} />
          </a>
          <p className="result-message">{result.message}</p>
          {result.note && <p className="disclaimer">{result.note}</p>}
        </div>
      </div>
      <div className="result-divider" />
      <div className="result-details-grid">
        <div className="detail-block">
          <div className="detail-heading"><span className="detail-heading-icon purple"><Icon name="spark" size={15} /></span> AI MODEL</div>
          <div className="detail-primary">{ml.prediction || "Not available"}</div>
          <div className="probability-row"><span>Prediction source</span><strong>{ml.model_source || "Not reported"}</strong></div>
          <div className="probability-row"><span>Phishing probability</span><strong>{Number.isFinite(ml.phishing_probability) ? `${ml.phishing_probability}%` : "—"}</strong></div>
          <div className="probability-track"><span style={{ width: `${Math.min(Math.max(Number(ml.phishing_probability) || 0, 0), 100)}%` }} /></div>
          <div className="probability-row legitimate-row"><span>Legitimate probability</span><strong>{Number.isFinite(ml.legitimate_probability) ? `${ml.legitimate_probability}%` : "—"}</strong></div>
          <div className="probability-track legitimate-track"><span style={{ width: `${Math.min(Math.max(Number(ml.legitimate_probability) || 0, 0), 100)}%` }} /></div>
        </div>
        <div className="detail-block">
          <div className="detail-heading"><span className="detail-heading-icon cyan"><Icon name="globe" size={15} /></span> DNS INTELLIGENCE</div>
          <div className="detail-primary">{scan.dns?.status === "loading" ? "Looking up…" : `${recordCount} records found`}</div>
          <div className="dns-summary">
            {Object.entries(dnsRecords).filter(([, records]) => records?.length).map(([type, records]) => (
              <span className="dns-tag" key={type}>{type}<b>{records.length}</b></span>
            ))}
            {scan.dns?.status === "error" && <span className="muted-copy">Lookup unavailable</span>}
            {!recordCount && scan.dns?.status !== "loading" && scan.dns?.status !== "error" && <span className="muted-copy">No DNS records returned</span>}
          </div>
          {scan.dns?.error && <div className="dns-error">{scan.dns.error}</div>}
        </div>
      </div>
      <div className="finding-section">
        <div className="detail-heading"><span className="detail-heading-icon amber"><Icon name="activity" size={15} /></span> SCAN FINDINGS <span className="finding-count">{scanFindings.length}</span></div>
        {scanFindings.length ? (
          <ul className="finding-list">{scanFindings.map((finding, index) => {
            const detail = (result.finding_details || []).find((item) => item.title === finding);
            return (
              <li key={`${finding}-${index}`}>
                <span className="finding-bullet" />
                <div className="finding-copy">
                  <span>{finding}</span>
                  {detail?.severity && <span className={`finding-severity ${detail.severity}`}>{detail.severity}</span>}
                  {detail?.evidence && <small>{detail.evidence}</small>}
                  {detail?.recommendation && <small>Recommendation: {detail.recommendation}</small>}
                </div>
              </li>
            );
          })}</ul>
        ) : websiteFindings.length ? (
          <div className="muted-copy">Website assessment findings are listed below.</div>
        ) : <div className="clean-finding"><Icon name="check" size={15} /> No other scan findings were reported.</div>}
      </div>
      <div className="transport-strip">
        <span className={`transport-icon ${analysis.uses_https ? "good" : "attention"}`}><Icon name="lock" size={15} /></span>
        <div><strong>{analysis.uses_https ? "HTTPS transport detected" : "Unencrypted HTTP connection"}</strong><span>{analysis.uses_https ? `Certificate validation: ${certificateVerified ? "verified" : certificateStatus}.` : "This address does not use HTTPS."}</span></div>
        <span className={`transport-state ${analysis.uses_https ? "good" : "attention"}`}>{analysis.uses_https ? "HTTPS" : "HTTP"}</span>
      </div>

      {/* SECURITY ANALYSIS DETAILS */}
      <div className="security-analysis-section">
        <div className="detail-heading">
          <span className="detail-heading-icon purple"><Icon name="shield" size={15} /></span>
          SECURITY ANALYSIS BREAKDOWN
        </div>

        <div className="result-details-grid">
          <div className="detail-block">
            <div className="detail-heading">
              {hasTrustScore ? "UNIFIED WEBSITE TRUST SCORE" : "LEGACY SCORE BREAKDOWN"}
            </div>
            {hasTrustScore && (
              <div className="detail-primary">{result.trust_score.toFixed(2)} / 100</div>
            )}
            {scoreExplanation?.components ? scoreExplanation.components.map((component) => (
              <div className="probability-row" key={component.key}>
                <span>{component.label}</span>
                <strong>
                  {component.risk_score === null
                    ? `Unavailable (${component.status})`
                    : `${Number(component.risk_score).toFixed(1)} risk · ${(component.effective_weight * 100).toFixed(0)}% weight`}
                </strong>
              </div>
            )) : Object.entries(result.score_breakdown || {}).map(([key, value]) => (
              <div className="probability-row" key={key}>
                <span>{key.replaceAll("_", " ").toUpperCase()}</span>
                <strong>
                  {value !== null && value !== undefined && Number.isFinite(Number(value))
                    ? Number(value).toFixed(1)
                    : "Unavailable"}
                </strong>
              </div>
            ))}
            {!hasTrustScore && (
              <p className="score-explanation-copy">
                A unified trust score was not recorded for this saved scan.
              </p>
            )}
            {scoreExplanation?.method && (
              <p className="score-explanation-copy">
                {scoreExplanation.method}{" "}
                {scoreExplanation.risk_score === null
                  ? "Risk score unavailable."
                  : `Composite risk: ${scoreExplanation.risk_score}/100; trust = 100 - risk.`}{" "}
                Coverage: {scoreExplanation.coverage_percent}%.
              </p>
            )}
            {!scoreExplanation?.components && !Object.keys(result.score_breakdown || {}).length && (
              <span className="muted-copy">Score breakdown unavailable</span>
            )}
          </div>

          <div className="detail-block">
            <div className="detail-heading">TLS CERTIFICATE</div>
            {(() => {
              const cert = result.certificate_analysis || {};
              const certStatus = getCertificateDisplayStatus(cert);
              const certVerified = isCertificateVerified(cert);
              return (
                <>
                  <div className={`detail-primary ${certVerified ? "text-good" : "text-warn"}`}>
                    {certStatus.replaceAll("_", " ").toUpperCase()}
                  </div>
                  <div className="probability-row"><span>Issuer</span><strong>{typeof cert.issuer === "string" ? cert.issuer : cert.issuer && typeof cert.issuer === "object" ? Object.values(cert.issuer).filter(Boolean).join(", ") : "—"}</strong></div>
                  <div className="probability-row"><span>Hostname match</span><strong>{cert.hostname_match === true ? "Yes" : cert.hostname_match === false ? "No" : "—"}</strong></div>
                  <div className="probability-row"><span>Days remaining</span><strong>{cert.days_remaining ?? "—"}</strong></div>
                  {cert.error && <div className="dns-error">{cert.error}</div>}
                </>
              );
            })()}
          </div>
        </div>

        <div className="finding-section">
          <div className="detail-heading">
            <span className="detail-heading-icon amber"><Icon name="shieldAlert" size={15} /></span>
            URLHAUS THREAT INTELLIGENCE
          </div>
          {(() => {
            const intel = result.threat_intelligence?.urlhaus || {};
            const details = intel.details || {};
            const malicious = intel.malicious === true || intel.status === "malicious";
            return (
              <>
                <div className={`verdict-pill ${malicious ? "danger" : intel.status === "not_found" ? "safe" : "attention"}`}>
                  <span className="status-dot" />
                  {malicious ? "MALICIOUS URL DETECTED" : intel.status === "not_found" ? "NOT FOUND IN URLHAUS" : "INTELLIGENCE UNAVAILABLE"}
                </div>
                {details.threat && <div className="probability-row"><span>Threat</span><strong>{details.threat}</strong></div>}
                {details.url_status && <div className="probability-row"><span>URL status</span><strong>{details.url_status}</strong></div>}
                {details.date_added && <div className="probability-row"><span>Reported on</span><strong>{details.date_added}</strong></div>}
                {details.reporter && <div className="probability-row"><span>Reporter</span><strong>{details.reporter}</strong></div>}
                {Array.isArray(details.tags) && details.tags.length > 0 && (
                  <div className="dns-summary">{details.tags.map(tag => <span className="dns-tag" key={tag}>{tag}</span>)}</div>
                )}
                {intel.error && <div className="dns-error">{intel.error}</div>}
                <p className="disclaimer">Not found in URLhaus does not guarantee that a website is safe.</p>
              </>
            );
          })()}
        </div>

        <div className="finding-section">
          <div className="detail-heading">
            <span className="detail-heading-icon cyan"><Icon name="globe" size={15} /></span>
            WEBSITE ANALYSIS
          </div>
          <div className="probability-row">
            <span>Assessment status</span>
            <strong>{website.status || "Unavailable"}</strong>
          </div>
          <div className="probability-row">
            <span>Security header checks</span>
            <strong>{website.security_header_status || "Unavailable"}</strong>
          </div>
          <div className="probability-row">
            <span>Redirect-chain checks</span>
            <strong>{website.redirect_status || "Unavailable"}</strong>
          </div>
          <div className="probability-row">
            <span>Cookie attribute checks</span>
            <strong>{website.cookie_status || "Unavailable"}</strong>
          </div>
          {website.https_enforcement && (
            <div className="probability-row">
              <span>HTTPS enforcement</span>
              <strong>{(website.https_enforcement.status || "unavailable").replaceAll("_", " ")}</strong>
            </div>
          )}
          {checkedHeaders.length > 0 && (
            <>
              <div className="probability-row">
                <span>Security headers present</span>
                <strong>{presentHeaderCount} / {checkedHeaders.length}</strong>
              </div>
              <div className="dns-summary website-header-tags">
                {websiteHeaders.map(([header, present]) => (
                  <span
                    className={`dns-tag security-header-tag ${present === null ? "not-applicable" : present ? "present" : "missing"}`}
                    key={header}
                  >
                    {header}: {present === null ? "N/A" : present ? "Present" : "Missing"}
                  </span>
                ))}
              </div>
            </>
          )}
          {redirectAnalysis && (
            <>
              <div className="probability-row">
                <span>Redirects observed</span>
                <strong>{redirectAnalysis.count}</strong>
              </div>
              <div className="probability-row">
                <span>Cross-origin redirects</span>
                <strong>{redirectAnalysis.cross_origin_count}</strong>
              </div>
              <div className="probability-row">
                <span>HTTPS downgrade</span>
                <strong>{redirectAnalysis.https_downgrade ? "Detected" : "Not observed"}</strong>
              </div>
              <div className="probability-row">
                <span>Redirect loop</span>
                <strong>{redirectAnalysis.loop_detected ? "Detected" : "Not observed"}</strong>
              </div>
              {redirectAnalysis.chain?.length > 0 && (
                <ul className="finding-list website-redirect-chain">
                  {redirectAnalysis.chain.map((hop, index) => (
                    <li key={`${hop.from}-${index}`}>
                      <span className="finding-bullet" />
                      <div className="finding-copy">
                        <span>HTTP {hop.status}: {displayRedirectTarget(hop.from)} → {displayRedirectTarget(hop.to)}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
              {redirectAnalysis.suspicious_patterns?.length > 0 && (
                <div className="website-analysis-note">
                  Redirect pattern requires review: {redirectAnalysis.suspicious_patterns.map((pattern) => pattern.type.replaceAll("_", " ")).join(", ")}.
                </div>
              )}
            </>
          )}
          {mixedContent.status && (
            <div className="probability-row">
              <span>Mixed content inspection</span>
              <strong>{mixedContent.status.replaceAll("_", " ")}</strong>
            </div>
          )}
          {mixedContent.resources?.length > 0 && (
            <div className="website-analysis-note">
              HTTP resource references observed ({mixedContent.resource_count || mixedContent.resources.length}): {mixedContent.resources.map((resource) => `${resource.element} → ${resource.hostname}`).join(", ")}
              {mixedContent.truncated ? " · Inspection is partial; the HTML sample or displayed-reference limit was reached." : ""}
            </div>
          )}
          {mixedContent.insecure_forms?.length > 0 && (
            <div className="website-analysis-note">
              Forms posting over HTTP ({mixedContent.form_count || mixedContent.insecure_forms.length}): {mixedContent.insecure_forms.join(", ")}
            </div>
          )}
          {mixedContent.status === "partial" && !mixedContent.resources?.length && (
            <div className="website-analysis-note">
              No mixed-content reference was observed in the sampled portion; additional page content was not inspected.
            </div>
          )}
          {observedCookies.length > 0 && (
            <>
              <div className="probability-row">
                <span>Cookies observed</span>
                <strong>{observedCookies.length}</strong>
              </div>
              {["secure", "http_only", "same_site"].map((attribute) => {
                const count = observedCookies.filter((cookie) =>
                  attribute === "same_site"
                    ? Boolean(cookie.same_site)
                    : cookie[attribute] === true,
                ).length;
                const label = attribute === "http_only"
                  ? "HttpOnly"
                  : attribute === "same_site"
                    ? "SameSite"
                    : "Secure";
                return (
                  <div className="probability-row" key={attribute}>
                    <span>Cookies with {label}</span>
                    <strong>{count} / {observedCookies.length}</strong>
                  </div>
                );
              })}
            </>
          )}
          {websiteFindings.length ? (
            <ul className="finding-list">{websiteFindings.map((item, index) => {
              const detail = (website.finding_details || []).find((finding) =>
                finding.title === item,
              ) || websiteFindingDetails.find((finding) => finding.title === item);
              return (
                <li key={`${item}-${index}`}>
                  <span className="finding-bullet" />
                  <div className="finding-copy">
                    <span>{typeof item === "string" ? item : item.title || JSON.stringify(item)}</span>
                    {detail?.severity && <span className={`finding-severity ${detail.severity}`}>{detail.severity}</span>}
                    {detail?.classification && <small className="finding-classification">{detail.classification.replaceAll("_", " ")}</small>}
                    {detail?.evidence && <small>{detail.evidence}</small>}
                    {detail?.recommendation && <small>Recommendation: {detail.recommendation}</small>}
                  </div>
                </li>
              );
            })}</ul>
          ) : website.status === "completed" ? (
            <div className="clean-finding"><Icon name="check" size={15} /> No website findings were reported by this assessment.</div>
          ) : (
            <div className="muted-copy">{website.error || "Website security checks were unavailable."}</div>
          )}
          <p className="website-assessment-scope">
            Passive assessment only: the scanner does not execute JavaScript. Mixed-content checks inspect at most 512 KB of returned HTML; dynamic or later-loaded resources are not covered.
          </p>
        </div>
      </div>
    </section>
  );
}

function EmptyState({ icon, title, description, action, onAction }) {
  return (
    <div className="empty-state">
      <div className="empty-icon"><Icon name={icon} size={25} /></div>
      <h3>{title}</h3><p>{description}</p>
      {action && <button className="text-button" onClick={onAction}>{action}<Icon name="chevron" size={15} /></button>}
    </div>
  );
}

function ScanTable({ scans, onSelect, onReport, compact = false }) {
  if (!scans.length) {
    return <EmptyState icon="clock" title="No scans yet" description="Your completed URL scans will appear here." />;
  }
  return (
    <div className="table-scroll">
      <table className="scan-table">
        <thead><tr><th>WEBSITE</th><th>VERDICT</th><th>RISK SCORE</th><th>SCANNED</th><th /></tr></thead>
        <tbody>
          {scans.slice(0, compact ? 4 : undefined).map((scan) => {
            const status = getScanStatus(scan.result);
            const tone = status.tone;
            const hasRiskScore = hasUnifiedRiskScore(scan.result);
            return (
              <tr key={scan.id} onClick={() => onSelect(scan)} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && onSelect(scan)}>
                <td><div className="table-domain"><span className="table-favicon"><Icon name="globe" size={14} /></span><span><strong>{scan.result.analysis?.domain || scan.result.url}</strong><small>{scan.result.url}</small></span></div></td>
                <td><span className={`table-verdict ${tone}`}><span className="status-dot" />{status.label}</span></td>
                <td><span className={`table-score ${tone}`}>{hasRiskScore ? scan.result.risk_score : "—"}{hasRiskScore && <small>/100</small>}</span></td>
                <td className="table-date">{formatDate(scan.scannedAt)}</td>
                <td className="scan-table-actions">
                  {onReport && (
                    <button
                      type="button"
                      className="table-report-button"
                      aria-label={`View security report for ${scan.result.analysis?.domain || scan.result.url}`}
                      onClick={(event) => { event.stopPropagation(); onReport(scan); }}
                    >
                      Report
                    </button>
                  )}
                  <Icon name="chevron" size={15} className="table-chevron" />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ThreatSummary({ scan }) {
  const ml = scan.result.ml_prediction || {};
  const dns = scan.dns?.dns_records || {};
  const recordCount = Object.values(dns).reduce((sum, records) => sum + (records?.length || 0), 0);
  return (
    <div className="threat-summary">
      <div className="threat-domain-row"><div className="threat-domain-icon"><Icon name="globe" size={16} /></div><div><strong>{scan.result.analysis?.domain || "Unknown domain"}</strong><span>{scan.result.analysis?.scheme?.toUpperCase()} · {scan.result.analysis?.uses_https ? "TLS transport" : "No HTTPS"}</span></div></div>
      <div className="threat-model-box"><div className="model-label"><span className="model-spark"><Icon name="spark" size={14} /></span> AI CLASSIFICATION <span className={`classification ${getVerdictTone(ml.prediction)}`}>{ml.prediction || "N/A"}</span></div><div className="model-bar"><span style={{ width: `${Math.min(Math.max(Number(ml.phishing_probability) || 0, 0), 100)}%` }} /></div><div className="model-foot"><span>Phishing likelihood</span><strong>{Number.isFinite(ml.phishing_probability) ? `${ml.phishing_probability}%` : "Not provided"}</strong></div></div>
      <div className="intel-facts">
        <div><span>Heuristic signals</span><strong>{scan.result.findings?.length || 0}</strong></div>
        <div><span>DNS records</span><strong>{scan.dns?.status === "loading" ? "…" : recordCount}</strong></div>
        <div><span>Transport</span><strong className={scan.result.analysis?.uses_https ? "text-good" : "text-warn"}>{scan.result.analysis?.uses_https ? "HTTPS" : "HTTP"}</strong></div>
      </div>
      {scan.dns?.status === "error" && <div className="inline-note"><Icon name="info" size={14} />DNS lookup failed: {scan.dns.error}</div>}
      <div className="intel-disclaimer">Signals are preliminary and should be considered alongside your own security controls.</div>
    </div>
  );
}

export default function App() {
  const [history, setHistory] = useState(readHistory);
  const historyRef = useRef(history);
  const [activeView, setActiveView] = useState("overview");
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [apiOnline, setApiOnline] = useState(false);
  const [apiError, setApiError] = useState("");
  const [mobileNavOpen, setMobileNavOpen] = useState(
    () => !window.matchMedia("(max-width: 920px)").matches,
  );

  const selectedScan = useMemo(
    () => history.find((scan) => scan.id === selectedScanId) || history[0] || null,
    [history, selectedScanId],
  );

  useEffect(() => {
    let active = true;
    getHealth().then(
      (data) => {
        if (active) {
          setApiOnline(data.status === "healthy");
          setApiError("");
        }
      },
      (error) => {
        if (active) {
          setApiOnline(false);
          setApiError(error.message);
        }
      },
    );
    const refresh = window.setInterval(() => {
      getHealth().then(
        (data) => {
          if (active) {
            setApiOnline(data.status === "healthy");
            setApiError("");
          }
        },
        (error) => {
          if (active) {
            setApiOnline(false);
            setApiError(error.message);
          }
        },
      );
    }, 30_000);
    return () => { active = false; window.clearInterval(refresh); };
  }, []);

  useEffect(() => {
    const viewportQuery = window.matchMedia("(max-width: 920px)");
    const syncSidebarToViewport = (event) => setMobileNavOpen(!event.matches);
    viewportQuery.addEventListener("change", syncSidebarToViewport);
    return () => viewportQuery.removeEventListener("change", syncSidebarToViewport);
  }, []);

  function persistHistory(nextHistory) {
    historyRef.current = nextHistory;
    setHistory(nextHistory);
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(nextHistory));
    } catch (error) {
      console.error("Could not save CYBERNOVA scan history.", error);
    }
  }

  function updateScanDns(scanId, dns) {
    const updatedHistory = historyRef.current.map((scan) =>
      scan.id === scanId ? { ...scan, dns } : scan,
    );
    persistHistory(updatedHistory);
  }

  async function handleScan(event) {
    event.preventDefault();
    setScanError("");
    let normalized;
    try {
      normalized = normalizeUrl(url);
    } catch (error) {
      setScanError(error.message);
      return;
    }

    setScanning(true);
    setSelectedScanId(null);
    try {
      const result = await scanUrl(normalized);
      const scan = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        scannedAt: new Date().toISOString(),
        result,
        dns: { status: "loading" },
      };
      const firstHistory = [scan, ...historyRef.current].slice(0, 100);
      persistHistory(firstHistory);
      setUrl("");
      setSelectedScanId(scan.id);
      setApiOnline(true);
      lookupDns(result.analysis.domain).then(
        (dns) => updateScanDns(scan.id, { status: "success", ...dns }),
        (error) => updateScanDns(scan.id, { status: "error", error: error.message }),
      );
    } catch (error) {
      setScanError(error.message);
      setApiOnline(false);
    } finally {
      setScanning(false);
    }
  }

  function selectScan(scan) {
    setSelectedScanId(scan.id);
    setActiveView("scanner");
  }

  function selectReport(scan) {
    setSelectedScanId(scan.id);
    setActiveView("report");
  }

  const pageInfo = {
    overview: ["Dashboard", "Monitor website trust and analyze suspicious URLs."],
    trust: ["Trust dashboard", "Review measured risk, evidence, component coverage, and limitations."],
    scanner: ["URL scanner", "Analyze a URL and inspect phishing and security signals."],
    history: ["Scan history", "Review previous URL analysis results."],
    intelligence: ["Threat intelligence", "Understand the signals behind your URL risk assessment."],
    "community-reports": ["Community threat reports", "Submit and review community-submitted suspicious URLs."],
    ssl: ["SSL certificate analysis", "Review transport security details from your latest scan."],
    "certificate-monitoring": ["Certificate monitoring", "Track certificate changes across monitored domains."],
    report: ["Security report", "Review or print the complete report for a saved scan."],
  }[activeView];

  return (
    <div className={`app-shell ${mobileNavOpen ? "sidebar-open" : "sidebar-closed"}`}>
      {mobileNavOpen && <button className="mobile-backdrop" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation" />}
      <div className={`sidebar-container ${mobileNavOpen ? "open" : ""}`}>
        <Sidebar
          activeView={activeView}
          onNavigate={setActiveView}
          apiOnline={apiOnline}
          onClose={() => {
            setMobileNavOpen(false);
          }}
        />
      </div>
      <main className="main-content">
        <SidebarHeader title={pageInfo[0]} subtitle={pageInfo[1]} onMenu={() => setMobileNavOpen((isOpen) => !isOpen)} />
        <div className="page-content">
          <div className="backend-banner">
            <span className={`status-dot ${apiOnline ? "online" : "offline"}`} />
            <span>{apiOnline ? "Connected to CYBERNOVA API" : "Backend not responding"}</span>
            <span className="backend-url">{API_BASE_URL}</span>
            {!apiOnline && <span className="backend-help">{apiError || "Start the FastAPI server to scan URLs."}</span>}
          </div>
          {activeView === "overview" && (
            <Dashboard
              history={history}
              currentScan={selectedScan}
              onSelect={selectScan}
              onReport={selectReport}
              onViewReport={selectReport}
              onNavigate={setActiveView}
              isRiskyScan={isRiskyScan}
              MetricCard={MetricCard}
              ScanTable={ScanTable}
              ThreatSummary={ThreatSummary}
              EmptyState={EmptyState}
              ScanResult={(props) => <ScanResult {...props} onViewReport={selectReport} />}
              composer={
                <ScanComposer
                  value={url}
                  onChange={(nextUrl) => { setUrl(nextUrl); setScanError(""); }}
                  onSubmit={handleScan}
                  scanning={scanning}
                  error={scanError}
                />
              }
            />
          )}
          {activeView === "scanner" && (
            <ScannerPage
              composer={
                <ScanComposer
                  value={url}
                  onChange={(nextUrl) => { setUrl(nextUrl); setScanError(""); }}
                  onSubmit={handleScan}
                  scanning={scanning}
                  error={scanError}
                />
              }
              scan={selectedScan}
              scanning={scanning}
              ScanResult={(props) => <ScanResult {...props} onViewReport={selectReport} />}
            />
          )}
          {activeView === "history" && <ScanHistoryPage history={history} onSelect={selectScan} onReport={selectReport} onNavigate={setActiveView} ScanTable={ScanTable} EmptyState={EmptyState} />}
          {activeView === "intelligence" && <ThreatIntelligencePage scan={selectedScan} onNavigate={setActiveView} EmptyState={EmptyState} ThreatSummary={ThreatSummary} />}
          {activeView === "community-reports" && <CommunityReportsPage />}
          {activeView === "ssl" && <SSLAnalysisPage scan={selectedScan} onNavigate={setActiveView} EmptyState={EmptyState} />}
          {activeView === "certificate-monitoring" && <CertificateMonitoringPage />}
          {activeView === "trust" && <TrustDashboard scan={selectedScan} onNavigate={setActiveView} onViewReport={() => selectedScan && selectReport(selectedScan)} EmptyState={EmptyState} />}
          {activeView === "report" && <SecurityReportPage scan={selectedScan} onNavigate={setActiveView} EmptyState={EmptyState} />}
          <footer className="page-footer"><span>CYBERNOVA SECURITY INTELLIGENCE</span><span>Scan results are preliminary assessments, not guarantees of safety.</span></footer>
        </div>
      </main>
      <div className="toast-aria" aria-live="polite" />
    </div>
  );
}
