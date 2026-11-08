import React from "react";
import Icon from "../components/Icon.jsx";
import { hasUnifiedRiskScore } from "../utils/riskScore.js";

function formatTime(value) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function displayTarget(value) {
  if (!value) return "Not available";
  try {
    const target = new URL(value);
    return `${target.protocol}//${target.host}${target.pathname || "/"}`;
  } catch {
    return String(value).split(/[?#]/, 1)[0];
  }
}

function readable(value) {
  if (value === null || value === undefined || value === "") return "Not available";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value).replaceAll("_", " ");
}

function ReportSection({ title, children }) {
  return (
    <section className="security-report-section">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function DataTable({ rows }) {
  return (
    <dl className="security-report-data">
      {rows.map(([label, value], index) => (
        <div key={`${label}-${index}`}><dt>{label}</dt><dd>{value ?? "Not available"}</dd></div>
      ))}
    </dl>
  );
}

export default function SecurityReportPage({ scan, onNavigate, EmptyState }) {
  if (!scan) {
    return (
      <section className="panel full-panel">
        <EmptyState
          icon="file"
          title="No completed scan report"
          description="Run a URL scan or select a result from scan history to view a comprehensive report."
          action="Open URL scanner"
          onAction={() => onNavigate("scanner")}
        />
      </section>
    );
  }

  const result = scan.result || {};
  const explanation = result.score_explanation || {};
  const unifiedScoreAvailable = hasUnifiedRiskScore(result);
  const components = Array.isArray(explanation.components) ? explanation.components : [];
  const ml = result.ml_prediction || {};
  const phishing = result.phishing_analysis || {};
  const intelligence = result.threat_intelligence || {};
  const sources = intelligence.sources && typeof intelligence.sources === "object"
    ? Object.entries(intelligence.sources)
    : Object.entries(intelligence.urlhaus ? { urlhaus: intelligence.urlhaus } : {});
  const community = intelligence.sources?.community || null;
  const communityDetails = community?.details && typeof community.details === "object"
    ? community.details
    : {};
  const certificate = result.certificate_analysis || {};
  const website = result.website_analysis || {};
  const websiteFindings = Array.isArray(website.finding_details) ? website.finding_details : [];
  const findings = Array.isArray(result.finding_details) ? result.finding_details : [];
  const recommendations = [...new Set(
    findings.map((finding) => finding.recommendation).filter(Boolean),
  )];
  const headers = website.security_headers && typeof website.security_headers === "object"
    ? Object.entries(website.security_headers)
    : [];
  const redirect = website.redirect_analysis || {};
  const mixedContent = website.mixed_content || {};
  const cookies = Array.isArray(website.cookies) ? website.cookies : [];
  const limitations = [
    ...(!unifiedScoreAvailable
      ? ["This saved scan has no unified risk-score explanation; any legacy numeric score is treated as unknown."]
      : []),
    ...(Array.isArray(explanation.limitations) ? explanation.limitations : []),
    "A low risk score or absence of known threat matches does not guarantee safety.",
    "Threat-feed no-match results apply only to the named source and time of lookup.",
    "Website assessment is passive. It does not execute JavaScript, authenticate, submit forms, or inspect content beyond the configured sample.",
    "Community reports are pseudonymous user submissions and are not proof of malicious activity.",
    "Certificate monitoring baselines are historical observations and are intentionally not included as a scan risk component.",
    ...(components.some((component) => component.risk_score === null || component.risk_score === undefined)
      ? ["Unavailable risk components were omitted and remaining component weights were normalized."]
      : []),
  ];

  return (
    <article className="security-report">
      <div className="security-report-toolbar no-print">
        <button type="button" className="text-button" onClick={() => onNavigate("history")}>
          <Icon name="chevron" size={14} /> Back to scan history
        </button>
        <button type="button" className="scan-button" onClick={() => window.print()}>
          <Icon name="file" size={15} /> Print / Save as PDF
        </button>
      </div>

      <header className="security-report-cover">
        <div className="security-report-brand">
  <img src="/cybernova-logo.png" alt="CYBERNOVA Global Threat Intelligence" />
</div>
        <span className="security-report-kicker">COMPREHENSIVE SECURITY REPORT</span>
        <h1>{result.analysis?.domain || displayTarget(result.url)}</h1>
        <p className="security-report-target">{displayTarget(result.url)} <span>· query and fragment omitted for privacy</span></p>
        <DataTable rows={[
          ["Scan timestamp", formatTime(scan.scannedAt)],
          ["Overall verdict", unifiedScoreAvailable ? result.verdict || "Unknown" : "Unknown"],
          ["Risk category", unifiedScoreAvailable ? result.risk_category || "Unknown" : "Unknown"],
          ["Risk score", unifiedScoreAvailable ? `${result.risk_score} / 100` : "Unavailable"],
          ["Derived trust score", unifiedScoreAvailable && Number.isFinite(result.trust_score) ? `${result.trust_score} / 100` : "Unavailable"],
        ]} />
        <p className="security-report-disclaimer">
          Automated assessment only. This report is not a certification and does not guarantee that the target is safe or malicious.
        </p>
      </header>

      <ReportSection title="Risk scoring breakdown">
        <p className="security-report-copy">
          {explanation.method || "Scoring methodology was not included in this saved scan."}
        </p>
        {components.length ? (
          <div className="security-report-table-wrap">
            <table className="security-report-table">
              <thead><tr><th>Component</th><th>Result</th><th>Configured weight</th><th>Effective weight</th><th>Availability</th></tr></thead>
              <tbody>{components.map((component) => (
                <tr key={component.key}>
                  <td>{component.label}</td>
                  <td>{component.risk_score === null || component.risk_score === undefined ? "Not scored" : component.risk_score}</td>
                  <td>{Number.isFinite(component.configured_weight) ? `${Math.round(component.configured_weight * 100)}%` : "Not available"}</td>
                  <td>{Number.isFinite(component.effective_weight) ? `${Math.round(component.effective_weight * 100)}%` : "Not available"}</td>
                  <td>{readable(component.status)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <p className="security-report-copy">Risk breakdown is unavailable for this saved result.</p>}
        <DataTable rows={[
          ["Risk score", unifiedScoreAvailable ? `${result.risk_score} / 100` : "Unavailable"],
          ["Trust score formula", "100 − risk score"],
          ["Score coverage", Number.isFinite(explanation.coverage_percent) ? `${explanation.coverage_percent}%` : "Not available"],
          ["Assessment scope", "Only measured, available components are included"],
        ]} />
      </ReportSection>

      <ReportSection title="Machine-learning and URL analysis">
        <DataTable rows={[
          ["Model status", readable(ml.status || ml.prediction)],
          ["Model source", ml.model_source || "Not reported"],
          ["Phishing probability", Number.isFinite(ml.phishing_probability) ? `${ml.phishing_probability}%` : "Unavailable"],
          ["Legitimate probability", Number.isFinite(ml.legitimate_probability) ? `${ml.legitimate_probability}%` : "Unavailable"],
          ["Rule-based status", readable(phishing.status)],
          ["Rule-based risk score", Number.isFinite(phishing.risk_score) ? `${phishing.risk_score} / 100` : "Unavailable"],
        ]} />
        <ReportFindingList findings={phishing.findings || []} />
      </ReportSection>

      <ReportSection title="Threat intelligence sources">
        <p className="security-report-copy">Source-level results are time-bound. A no-match does not establish that a URL is safe.</p>
        {sources.length ? (
          <div className="security-report-table-wrap">
            <table className="security-report-table">
              <thead><tr><th>Source</th><th>Status</th><th>Category</th><th>Confidence</th><th>Last checked</th></tr></thead>
              <tbody>{sources.map(([key, source]) => (
                <tr key={key}>
                  <td>{source?.source || key}</td>
                  <td>{readable(source?.status)}</td>
                  <td>{readable(source?.category || source?.details?.categories && Object.keys(source.details.categories).join(", "))}</td>
                  <td>{source?.confidence || "Not provided"}</td>
                  <td>{formatTime(source?.checked_at)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <p className="security-report-copy">Threat-intelligence source results were unavailable.</p>}
        {community && (
          <div className="security-report-community">
            <strong>Community report summary · {readable(community.status)}</strong>
            <DataTable rows={[
              ["Reports", Number.isFinite(communityDetails.report_count) ? communityDetails.report_count : 0],
              ["Distinct pseudonymous reporters", Number.isFinite(communityDetails.distinct_reporters) ? communityDetails.distinct_reporters : 0],
              ["Moderator-reviewed reporters", Number.isFinite(communityDetails.reviewed_reporters) ? communityDetails.reviewed_reporters : 0],
              ["Categories", communityDetails.categories && Object.keys(communityDetails.categories).join(", ") || "Not reported"],
            ]} />
            <p>Reporter identity, evidence text, query strings, and moderation notes are not included in this report.</p>
          </div>
        )}
      </ReportSection>

      <ReportSection title="TLS certificate analysis">
        <DataTable rows={[
          ["Certificate status", readable(certificate.status)],
          ["Validation status", readable(certificate.verification?.status)],
          ["Hostname match", certificate.hostname_match === true ? "Verified" : certificate.hostname_match === false ? "Mismatch" : "Unknown"],
          ["Issuer", typeof certificate.issuer === "string" ? certificate.issuer : certificate.issuer && typeof certificate.issuer === "object" ? Object.values(certificate.issuer).filter(Boolean).join(", ") : "Not available"],
          ["Subject", typeof certificate.subject === "string" ? certificate.subject : certificate.subject && typeof certificate.subject === "object" ? Object.values(certificate.subject).filter(Boolean).join(", ") : "Not available"],
          ["TLS protocol", certificate.tls_version || certificate.protocol || "Not available"],
          ["Cipher", certificate.cipher?.name || certificate.cipher || "Not available"],
          ["Valid from", formatTime(certificate.not_before)],
          ["Expires", formatTime(certificate.expires_at)],
          ["Days remaining", Number.isFinite(certificate.days_remaining) ? certificate.days_remaining : "Not available"],
        ]} />
        <ReportFindingList findings={certificate.finding_details || []} />
      </ReportSection>

      <ReportSection title="Passive website security assessment">
        <DataTable rows={[
          ["Assessment status", readable(website.status)],
          ["Security-header check status", readable(website.security_header_status)],
          ["HTTPS enforcement", readable(website.https_enforcement?.status)],
          ["Redirect check status", readable(website.redirect_status)],
          ["Redirects observed", Number.isFinite(redirect.count) ? redirect.count : "Unavailable"],
          ["Cross-origin redirects", Number.isFinite(redirect.cross_origin_count) ? redirect.cross_origin_count : "Unavailable"],
          ["Redirect loop", redirect.loop_detected === true ? "Detected" : redirect.loop_detected === false ? "Not observed" : "Unknown"],
          ["Mixed-content inspection", readable(mixedContent.status)],
          ["Cookies observed", cookies.length],
        ]} />
        {headers.length > 0 && (
          <div className="security-report-table-wrap">
            <table className="security-report-table">
              <thead><tr><th>Security header</th><th>Presence</th></tr></thead>
              <tbody>{headers.map(([header, present]) => (
                <tr key={header}><td>{header}</td><td>{present === true ? "Present" : present === false ? "Missing" : "Not checked"}</td></tr>
              ))}</tbody>
            </table>
          </div>
        )}
        {redirect.chain?.length > 0 && (
          <div className="security-report-redirects">
            <h3>Observed redirect chain</h3>
            <ol>{redirect.chain.map((hop, index) => (
              <li key={`${index}-${hop.status}`}>HTTP {hop.status}: {displayTarget(hop.from)} → {displayTarget(hop.to)}</li>
            ))}</ol>
          </div>
        )}
        <ReportFindingList findings={websiteFindings} />
      </ReportSection>

      <ReportSection title="Evidence and findings">
        {findings.length ? <ReportFindingList findings={findings} /> : (
          <p className="security-report-copy">No finding details were included. This is not proof of a risk-free target.</p>
        )}
      </ReportSection>

      <ReportSection title="Remediation recommendations">
        {recommendations.length ? (
          <ol className="security-report-recommendations">
            {recommendations.map((recommendation, index) => <li key={`${index}-${recommendation}`}>{recommendation}</li>)}
          </ol>
        ) : <p className="security-report-copy">No finding-specific recommendations were included.</p>}
      </ReportSection>

      <ReportSection title="Assessment limitations">
        <ul className="security-report-limitations">{[...new Set(limitations)].map((limitation, index) => <li key={`${index}-${limitation}`}>{limitation}</li>)}</ul>
      </ReportSection>

      <footer className="security-report-footer">
        CYBERNOVA · Automated security assessment · Risk and trust scores reflect recorded evidence only and are not guarantees of safety.
      </footer>
    </article>
  );
}

function ReportFindingList({ findings }) {
  const items = Array.isArray(findings) ? findings : [];
  if (!items.length) return <p className="security-report-copy">No findings were reported by this analysis component.</p>;
  return (
    <div className="security-report-findings">
      {items.map((finding, index) => {
        const detail = typeof finding === "string" ? { title: finding } : finding || {};
        return (
          <article className="security-report-finding" key={`${detail.code || detail.title || "finding"}-${index}`}>
            <div className="security-report-finding-heading">
              <strong>{detail.title || detail.code || "Finding"}</strong>
              {detail.severity && <span className={`finding-severity ${String(detail.severity).toLowerCase()}`}>{detail.severity}</span>}
            </div>
            {detail.classification && <small>Classification: {readable(detail.classification)}</small>}
            {detail.evidence && <p>Evidence: {detail.evidence}</p>}
            {detail.recommendation && <p>Recommendation: {detail.recommendation}</p>}
          </article>
        );
      })}
    </div>
  );
}
