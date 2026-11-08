import React from "react";
import Icon from "../components/Icon.jsx";
import {
  getCertificateDisplayStatus,
  isCertificateVerified,
} from "../utils/certificate.js";
import { hasUnifiedRiskScore } from "../utils/riskScore.js";

function scoreNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function riskTone(category, score) {
  const normalized = String(category || "").toLowerCase();
  if (normalized === "critical" || normalized === "high" || (score !== null && score >= 65)) {
    return "critical";
  }
  if (normalized === "medium" || (score !== null && score >= 35)) return "suspicious";
  if (normalized === "low" && score !== null) return "low";
  return "unknown";
}

function RiskIndicator({ score, category }) {
  const tone = riskTone(category, score);
  const shownScore = score === null ? "—" : Math.round(score);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const offset = score === null
    ? circumference
    : circumference * (1 - Math.min(Math.max(score, 0), 100) / 100);
  return (
    <div className={`trust-risk-indicator ${tone}`} role="img" aria-label={
      score === null
        ? "Overall risk score unavailable"
        : `${category || "Unknown"} risk: ${shownScore} out of 100`
    }>
      <svg viewBox="0 0 128 128" aria-hidden="true">
        <circle className="trust-risk-track" cx="64" cy="64" r={radius} />
        <circle
          className="trust-risk-progress"
          cx="64"
          cy="64"
          r={radius}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div><strong>{shownScore}</strong><span>/100</span></div>
      <small>RISK SCORE</small>
    </div>
  );
}

function StatusPill({ status, label }) {
  const normalized = String(status || "unavailable").toLowerCase();
  const tone = ["low", "measured", "completed", "valid", "verified", "not_found"].includes(normalized)
    ? "available"
    : ["malicious", "critical", "high", "invalid", "expired"].includes(normalized)
      ? "adverse"
      : "unknown";
  return <span className={`trust-status-pill ${tone}`}>{label || normalized.replaceAll("_", " ")}</span>;
}

function AssessmentCard({ title, icon, status, children }) {
  return (
    <article className="panel trust-assessment-card">
      <div className="trust-card-heading">
        <span className="trust-card-icon"><Icon name={icon} size={16} /></span>
        <h3>{title}</h3>
        <StatusPill status={status} />
      </div>
      {children}
    </article>
  );
}

function showValue(value, suffix = "") {
  return typeof value === "number" && Number.isFinite(value)
    ? `${value}${suffix}`
    : "Not available";
}

function SourceResult({ name, source }) {
  const details = source?.details && typeof source.details === "object" ? source.details : {};
  const status = source?.status || "unavailable";
  return (
    <div className="trust-source-row">
      <span>{name}</span>
      <div>
        <StatusPill status={status} />
        {details.report_count > 0 && (
          <small>
            {details.report_count} report{details.report_count === 1 ? "" : "s"} ·{" "}
            {details.distinct_reporters || 0} distinct reporter{details.distinct_reporters === 1 ? "" : "s"}
          </small>
        )}
        {source?.checked_at && <small>Checked {new Date(source.checked_at).toLocaleString()}</small>}
      </div>
    </div>
  );
}

export default function TrustDashboard({ scan, onNavigate, onViewReport, EmptyState }) {
  if (!scan) {
    return (
      <section className="panel full-panel">
        <EmptyState
          icon="shield"
          title="Trust assessment is not available yet"
          description="Run a URL scan to see measured risk, component availability, findings, and limitations."
          action="Open URL scanner"
          onAction={() => onNavigate("scanner")}
        />
      </section>
    );
  }

  const result = scan.result || {};
  const ml = result.ml_prediction || {};
  const phishing = result.phishing_analysis || {};
  const intelligence = result.threat_intelligence || {};
  const sources = intelligence.sources && typeof intelligence.sources === "object"
    ? intelligence.sources
    : { urlhaus: intelligence.urlhaus || { status: intelligence.status || "unavailable" } };
  const community = sources.community || {};
  const certificate = result.certificate_analysis || {};
  const certificateVerified = isCertificateVerified(certificate);
  const certificateStatus = getCertificateDisplayStatus(certificate);
  const website = result.website_analysis || {};
  const unifiedScoreAvailable = hasUnifiedRiskScore(result);
  const score = unifiedScoreAvailable ? scoreNumber(result.risk_score) : null;
  const trustScore = unifiedScoreAvailable ? scoreNumber(result.trust_score) : null;
  const category = unifiedScoreAvailable ? result.risk_category || "Unknown" : "Unknown";
  const tone = riskTone(category, score);
  const explanation = result.score_explanation || {};
  const components = Array.isArray(explanation.components) ? explanation.components : [];
  const findingDetails = Array.isArray(result.finding_details) ? result.finding_details : [];
  const keyFindings = findingDetails.filter((finding) =>
    ["high", "critical"].includes(String(finding.severity || "").toLowerCase()),
  );
  const recommendations = [...new Set(
    findingDetails
      .map((finding) => finding.recommendation)
      .filter((recommendation) => typeof recommendation === "string" && recommendation.trim()),
  )];
  const headers = website.security_headers && typeof website.security_headers === "object"
    ? Object.entries(website.security_headers)
    : [];
  const checkedHeaders = headers.filter(([, present]) => present !== null);
  const presentHeaders = checkedHeaders.filter(([, present]) => present === true).length;
  const redirects = website.redirect_analysis || {};
  const websiteStatus = website.status || "unavailable";
  const threatSources = Object.entries(sources);
  const unavailableComponents = components.filter((component) =>
    component.risk_score === null || component.risk_score === undefined,
  );
  const limitations = [
    ...(!unifiedScoreAvailable
      ? ["This saved scan has no unified risk-score explanation; any legacy numeric score is treated as unknown."]
      : []),
    ...(unavailableComponents.length
      ? [`Unavailable score components were excluded: ${unavailableComponents.map((item) => item.label).join(", ")}.`]
      : []),
    ...(Array.isArray(explanation.limitations) ? explanation.limitations : []),
    "A low assessed risk is not a guarantee of safety; new, targeted, or unreported threats may be missed.",
    "Website checks are passive; dynamic content is not executed and mixed-content inspection is limited to a bounded static sample.",
    ...(certificateStatus === "valid" && !certificateVerified
      ? ["Certificate status is not shown as verified because required validation checks did not all succeed."]
      : []),
    ...(community.status === "unverified" || community.status === "reviewed"
      ? ["Community submissions are reports, not proof; pseudonymous reporter counts do not verify distinct real people."]
      : []),
  ];

  return (
    <div className="trust-dashboard">
      <section className={`panel trust-hero ${tone}`}>
        <div className="trust-hero-copy">
          <div className="eyebrow"><span className="eyebrow-line" /> UNIFIED WEBSITE TRUST ASSESSMENT</div>
          <h2>{result.analysis?.domain || result.url || "Scan target"}</h2>
          <p>Assessment from {new Date(scan.scannedAt).toLocaleString()}</p>
          <div className={`trust-verdict ${tone}`}>
            <span className="status-dot" />
            {score === null ? "Unknown / unavailable" : `${category} risk`}
            {result.verdict && score !== null ? ` · ${result.verdict}` : ""}
          </div>
          <p className="trust-disclaimer">
            Risk and trust scores summarize only the evidence available in this scan. They do not certify a website as safe.
          </p>
          <button type="button" className="text-button trust-report-action" onClick={onViewReport}>
            View comprehensive report <Icon name="chevron" size={14} />
          </button>
        </div>
        <div className="trust-score-pair">
          <RiskIndicator score={score} category={category} />
          <div className="trust-derived-score">
            <span>DERIVED TRUST SCORE</span>
            <strong>{trustScore === null ? "—" : trustScore.toFixed(1)}<small>/100</small></strong>
            <p>{trustScore === null ? "Unavailable when risk cannot be scored." : "Calculated as 100 − overall risk score."}</p>
          </div>
        </div>
      </section>

      <section className="trust-assessment-grid">
        <AssessmentCard title="Machine-learning model" icon="spark" status={ml.status || ml.model_source || "unavailable"}>
          <div className="trust-primary-value">{showValue(ml.phishing_probability, "%")} phishing probability</div>
          <div className="trust-progress"><span style={{ width: `${Math.min(Math.max(ml.phishing_probability || 0, 0), 100)}%` }} /></div>
          <div className="trust-detail-row"><span>Model output</span><strong>{ml.prediction || "Not available"}</strong></div>
          <div className="trust-detail-row"><span>Model source</span><strong>{ml.model_source || "Not reported"}</strong></div>
          <div className="trust-detail-row"><span>Legitimate probability</span><strong>{showValue(ml.legitimate_probability, "%")}</strong></div>
          {ml.error && <p className="trust-muted">{ml.error}</p>}
        </AssessmentCard>

        <AssessmentCard title="URL rule-based analysis" icon="activity" status={phishing.status || "unavailable"}>
          <div className="trust-primary-value">{showValue(phishing.risk_score)}<small> / 100 risk</small></div>
          <div className="trust-detail-row"><span>Heuristic findings</span><strong>{Array.isArray(phishing.findings) ? phishing.findings.length : 0}</strong></div>
          {(phishing.findings || []).slice(0, 4).map((finding, index) => (
            <div className="trust-inline-finding" key={`${finding.code || finding.title}-${index}`}>
              <strong>{finding.title || finding.code || "Rule finding"}</strong>
              {finding.evidence && <small>{finding.evidence}</small>}
            </div>
          ))}
          {phishing.error && <p className="trust-muted">{phishing.error}</p>}
        </AssessmentCard>

        <AssessmentCard title="Threat intelligence" icon="globe" status={intelligence.status || "unavailable"}>
          <p className="trust-card-note">A source no-match is not proof of safety.</p>
          <div className="trust-source-list">
            {threatSources.map(([key, source]) => (
              <SourceResult key={key} name={source?.source || key} source={source || { status: "unavailable" }} />
            ))}
            {!threatSources.length && <p className="trust-muted">No source results were returned.</p>}
          </div>
        </AssessmentCard>

        <AssessmentCard title="TLS / certificate security" icon="lock" status={certificateVerified ? "verified" : certificateStatus}>
          <div className="trust-primary-value">{certificateStatus.replaceAll("_", " ")}</div>
          <div className="trust-detail-row"><span>Hostname match</span><strong>{certificate.hostname_match === true ? "Verified" : certificate.hostname_match === false ? "Mismatch" : "Unknown"}</strong></div>
          <div className="trust-detail-row"><span>Issuer</span><strong>{typeof certificate.issuer === "string" ? certificate.issuer : certificate.issuer && typeof certificate.issuer === "object" ? Object.values(certificate.issuer).filter(Boolean).join(", ") : "Not available"}</strong></div>
          <div className="trust-detail-row"><span>Days remaining</span><strong>{showValue(certificate.days_remaining)}</strong></div>
          <div className="trust-detail-row"><span>Validation checks</span><strong>{certificate.verification?.status || "Unavailable"}</strong></div>
          {certificate.error && <p className="trust-muted">{certificate.error}</p>}
        </AssessmentCard>

        <AssessmentCard title="Passive website assessment" icon="shield" status={websiteStatus}>
          <div className="trust-primary-value">{Array.isArray(website.findings) ? website.findings.length : 0} website finding(s)</div>
          <div className="trust-detail-row"><span>Security headers</span><strong>{checkedHeaders.length ? `${presentHeaders} / ${checkedHeaders.length} present` : website.security_header_status || "Unavailable"}</strong></div>
          <div className="trust-detail-row"><span>Redirects observed</span><strong>{Number.isFinite(redirects.count) ? redirects.count : "Unavailable"}</strong></div>
          <div className="trust-detail-row"><span>Cross-origin redirects</span><strong>{Number.isFinite(redirects.cross_origin_count) ? redirects.cross_origin_count : "Unavailable"}</strong></div>
          <div className="trust-detail-row"><span>Redirect loop</span><strong>{redirects.loop_detected === true ? "Detected" : redirects.loop_detected === false ? "Not observed" : "Unknown"}</strong></div>
          <div className="trust-detail-row"><span>Mixed-content inspection</span><strong>{website.mixed_content?.status || "Unavailable"}</strong></div>
          {headers.length > 0 && (
            <div className="trust-header-list">
              {headers.map(([header, present]) => (
                <span className={present === true ? "present" : present === false ? "missing" : "unknown"} key={header}>
                  {header}: {present === true ? "present" : present === false ? "missing" : "not checked"}
                </span>
              ))}
            </div>
          )}
          {website.error && <p className="trust-muted">{website.error}</p>}
        </AssessmentCard>

        <AssessmentCard title="Explainable risk components" icon="target" status={score === null ? "unavailable" : "measured"}>
          {components.length ? components.map((component) => (
            <div className="trust-component-row" key={component.key}>
              <div><strong>{component.label}</strong><small>{component.status || "status unavailable"}</small></div>
              <span>{component.risk_score === null || component.risk_score === undefined
                ? "Not scored"
                : `${Number(component.risk_score).toFixed(1)} · ${Number.isFinite(component.effective_weight) ? `${Math.round(component.effective_weight * 100)}% weight` : "weight unavailable"}`}</span>
            </div>
          )) : <p className="trust-muted">Risk component breakdown was not included in this saved scan.</p>}
          <p className="trust-card-note">{explanation.method || "Scoring method not available in this saved result."}</p>
        </AssessmentCard>
      </section>

      <section className="panel trust-findings-panel">
        <div className="panel-header">
          <div><h2>High and critical findings</h2><p>Evidence and recommended actions from this scan.</p></div>
          <span className="count-chip">{keyFindings.length} findings</span>
        </div>
        {keyFindings.length ? (
          <div className="trust-findings-list">
            {keyFindings.map((finding, index) => (
              <article className="trust-finding-item" key={`${finding.code || finding.title}-${index}`}>
                <div className={`finding-severity ${String(finding.severity).toLowerCase()}`}>{finding.severity}</div>
                <div><h3>{finding.title}</h3><p>{finding.evidence || "No additional evidence was recorded."}</p>
                  {finding.recommendation && <small>Recommended action: {finding.recommendation}</small>}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <div className="trust-no-critical">
            <Icon name="info" size={16} />
            No high or critical findings were recorded. This does not mean the target is risk-free.
          </div>
        )}
      </section>

      <section className="trust-bottom-grid">
        <article className="panel trust-recommendations">
          <div className="panel-header"><div><h2>Remediation recommendations</h2><p>Actions derived from recorded finding details.</p></div></div>
          {recommendations.length ? (
            <ul>{recommendations.map((recommendation, index) => <li key={`${index}-${recommendation}`}>{recommendation}</li>)}</ul>
          ) : <p className="trust-muted trust-panel-padding">No finding-specific recommendations were included.</p>}
        </article>
        <article className="panel trust-recommendations">
          <div className="panel-header"><div><h2>Coverage and limitations</h2><p>What this score does not establish.</p></div></div>
          <ul>{[...new Set(limitations)].map((limitation, index) => <li key={`${index}-${limitation}`}>{limitation}</li>)}</ul>
        </article>
      </section>
    </div>
  );
}
