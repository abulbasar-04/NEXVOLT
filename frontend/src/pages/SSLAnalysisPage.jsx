import React from "react";
import Icon from "../components/Icon.jsx";
import {
  getCertificateDisplayStatus,
  isCertificateVerified,
} from "../utils/certificate.js";

function displayName(value) {
  return String(value || "unavailable").replaceAll("_", " ");
}

function formatName(value) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return "Not available";
  return Object.values(value).filter(Boolean).join(", ") || "Not available";
}

function formatDate(value) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function AnalysisCheck({ label, status }) {
  return (
    <div className="probability-row">
      <span>{label}</span>
      <strong>{displayName(status)}</strong>
    </div>
  );
}

export default function SSLAnalysisPage({ scan, onNavigate, EmptyState }) {
  if (!scan) {
    return (
      <section className="panel full-panel" style={{ padding: 30 }}>
        <EmptyState
          icon="lock"
          title="No URL analyzed"
          description="Run a URL scan to check HTTPS and certificate security."
          action="Scan a URL"
          onAction={() => onNavigate("scanner")}
        />
      </section>
    );
  }

  const result = scan.result || {};
  const cert = result.certificate_analysis || {};
  const analysis = result.analysis || {};
  const verification = cert.verification || {};
  const chain = cert.certificate_chain || {};
  const trust = cert.trust_intelligence || {};
  const ct = trust.certificate_transparency || {};
  const revocation = trust.revocation || { status: "unsupported" };
  const findings = Array.isArray(cert.finding_details) ? cert.finding_details : [];
  const verified = isCertificateVerified(cert);
  const status = getCertificateDisplayStatus(cert);
  const statusLabels = {
    valid: "Certificate Verified",
    unverified: "Validation Incomplete",
    expired: "Certificate Expired",
    invalid: "Certificate Invalid",
    unavailable: "Certificate Unavailable",
    unsupported: "Check Unsupported",
    not_https: "HTTPS Not Used",
    blocked: "Destination Blocked",
    invalid_url: "Invalid URL",
  };
  const statusLabel = statusLabels[status] || displayName(status);
  const days = cert.days_remaining === null || cert.days_remaining === undefined
    ? null
    : Number.isFinite(Number(cert.days_remaining))
      ? Number(cert.days_remaining)
      : null;
  const cipher = typeof cert.cipher === "string"
    ? cert.cipher
    : cert.cipher?.name
      ? `${cert.cipher.name} (${cert.cipher.bits ?? "?"} bits)`
      : "Not available";
  const key = cert.public_key || {};
  const signature = cert.signature || {};
  const tlsAssessment = cert.tls_assessment || {};
  const chainCertificates = Array.isArray(chain.certificates)
    ? chain.certificates
    : [];
  const ctEntries = Array.isArray(ct.entries) ? ct.entries : [];
  const details = [
    ["Transport Scheme", analysis.scheme?.toUpperCase() || "Unknown"],
    ["Certificate Issuer", formatName(cert.issuer)],
    ["Certificate Subject", formatName(cert.subject)],
    ["Valid From", formatDate(cert.not_before)],
    ["Expires At", formatDate(cert.expires_at)],
    ["Days Remaining", days !== null ? days : "Not available"],
    ["Hostname", cert.hostname || analysis.domain || "Not available"],
    ["Hostname Match", cert.hostname_match === true ? "Verified" : cert.hostname_match === false ? "Failed" : "Not verified"],
    ["TLS Protocol", cert.tls_version || "Not available"],
    ["Negotiated Cipher", cipher],
    ["Public Key", key.algorithm ? `${key.algorithm}${key.key_size ? ` · ${key.key_size} bits` : ""}` : "Not available"],
    ["Signature Algorithm", signature.algorithm || "Not available"],
    ["SHA-256 Fingerprint", cert.sha256_fingerprint || "Not available"],
    [
      "Subject Alternative Names",
      Array.isArray(cert.subject_alt_names) && cert.subject_alt_names.length
        ? cert.subject_alt_names
            .map((name) => typeof name === "string" ? name : name.value || JSON.stringify(name))
            .join(", ")
        : "Not available",
    ],
  ];

  return (
    <div className="ssl-layout">
      <section className="panel ssl-hero-panel" style={{ padding: 25 }}>
        <div className="ssl-hero-top">
          <div
            className={`ssl-large-icon ${verified ? "good" : "attention"}`}
            style={{ width: 60, height: 60 }}
          >
            <Icon name="lock" size={30} />
          </div>

          <span className={`verdict-pill ${verified ? "safe" : "warning"}`}>
            <span className="status-dot" />
            {statusLabel}
          </span>
        </div>

        <div className="section-kicker">TLS CERTIFICATE ANALYSIS</div>

        <h2 style={{ fontSize: 25 }}>
          {verified
            ? "Required certificate checks passed"
            : "Certificate verification is incomplete or failed"}
        </h2>

        <p className="ssl-host" style={{ fontSize: 14 }}>
          {result.url || "Unknown website"}
        </p>

        <div className="ssl-status-banner" style={{ fontSize: 14 }}>
          <Icon name={verified ? "check" : "info"} size={18} />
          <span>
            {cert.error ||
              (verified
                ? "Validity dates, hostname, and certificate chain were verified using the system trust store."
                : "This result is not marked valid because one or more required checks did not pass or were not reported.")}
          </span>
        </div>

        {days !== null && (
          <div className="ssl-status-banner" style={{ fontSize: 14 }}>
            <Icon name="clock" size={18} />
            <span>
              {days < 0
                ? `Certificate expired ${Math.abs(days)} day(s) ago.`
                : days === 0
                  ? "Certificate expires today."
                  : `Certificate expires in ${days} day(s).`}
            </span>
          </div>
        )}
      </section>

      <section className="panel cert-panel">
        <div className="panel-header">
          <div>
            <h2>Certificate Details</h2>
            <p>Certificate metadata and negotiated TLS configuration</p>
          </div>
          <span className="metadata-label">TLS ANALYSIS</span>
        </div>

        <div className="cert-details">
          {details.map(([label, value]) => (
            <div key={label} style={{ minHeight: 50, fontSize: 14 }}>
              <span>{label}</span>
              <strong
                style={{
                  overflowWrap: "anywhere",
                  maxWidth: "65%",
                  color: label === "Certificate Status"
                    ? verified
                      ? "var(--success)"
                      : "var(--warning)"
                    : "var(--text-primary)",
                }}
              >
                {value}
              </strong>
            </div>
          ))}
        </div>

        <div className="finding-section">
          <div className="detail-heading">
            <span className="detail-heading-icon cyan"><Icon name="shield" size={15} /></span>
            VALIDATION CHECKS
          </div>
          <AnalysisCheck label="Overall validation" status={verification.status} />
          <AnalysisCheck label="Validity dates" status={verification.validity_dates} />
          <AnalysisCheck label="Hostname verification" status={verification.hostname} />
          <AnalysisCheck label="Certificate chain trust" status={verification.chain} />
          <AnalysisCheck label="Self-signed certificate" status={verification.self_signed} />
          <AnalysisCheck label="System CA trust" status={trust.ca_trust?.status} />
          <AnalysisCheck label="Known CA distrust database" status={trust.known_distrust?.status} />
          {trust.ca_trust?.message && <p className="score-explanation-copy">{trust.ca_trust.message}</p>}
        </div>

        <div className="finding-section">
          <div className="detail-heading">
            <span className="detail-heading-icon purple"><Icon name="lock" size={15} /></span>
            CERTIFICATE CHAIN
            <span className="finding-count">{chainCertificates.length}</span>
          </div>
          <AnalysisCheck label="Chain details" status={chain.status} />
          <AnalysisCheck label="Chain verification" status={chain.verification} />
          {chain.message && <p className="score-explanation-copy">{chain.message}</p>}
          {chainCertificates.length > 0 ? (
            <ul className="finding-list">
              {chainCertificates.map((item, index) => (
                <li key={`${item.sha256_fingerprint || item.subject}-${index}`}>
                  <span className="finding-bullet" />
                  <div className="finding-copy">
                    <span>{formatName(item.subject)}</span>
                    <small>Issuer: {formatName(item.issuer)}</small>
                    {item.sha256_fingerprint && <small>SHA-256: {item.sha256_fingerprint}</small>}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted-copy">Certificate chain certificates were not exposed by this Python runtime; chain trust may still be verified by the TLS handshake.</p>
          )}
        </div>

        <div className="finding-section">
          <div className="detail-heading">
            <span className="detail-heading-icon amber"><Icon name="activity" size={15} /></span>
            TLS SECURITY
          </div>
          <AnalysisCheck label="Protocol assessment" status={tlsAssessment.protocol_status} />
          <AnalysisCheck label="Cipher assessment" status={tlsAssessment.cipher_status} />
          <AnalysisCheck label="Public key analysis" status={key.status} />
          <AnalysisCheck label="Signature analysis" status={signature.status} />
        </div>

        <div className="finding-section">
          <div className="detail-heading">
            <span className="detail-heading-icon cyan"><Icon name="globe" size={15} /></span>
            CERTIFICATE TRUST INTELLIGENCE
          </div>
          <AnalysisCheck label="Certificate Transparency lookup" status={ct.status} />
          {ct.provider && <div className="probability-row"><span>CT provider</span><strong>{ct.provider}</strong></div>}
          {ct.entry_count !== null && ct.entry_count !== undefined && (
            <div className="probability-row"><span>Indexed issuance records</span><strong>{ct.entry_count}</strong></div>
          )}
          {ct.error && <div className="dns-error">{ct.error}</div>}
          {ctEntries.length > 0 && (
            <ul className="finding-list">
              {ctEntries.map((entry, index) => (
                <li key={`${entry.id || entry.not_before}-${index}`}>
                  <span className="finding-bullet" />
                  <div className="finding-copy">
                    <span>{entry.issuer || "Issuer unavailable"}</span>
                    <small>{entry.not_before || "Issue date unavailable"} – {entry.not_after || "Expiry unavailable"}</small>
                    {entry.matching_names && <small>{entry.matching_names}</small>}
                  </div>
                </li>
              ))}
            </ul>
          )}
          <AnalysisCheck label="Revocation status (OCSP/CRL)" status={revocation.status} />
          {revocation.message && <p className="score-explanation-copy">{revocation.message}</p>}
          {trust.known_distrust?.message && <p className="score-explanation-copy">{trust.known_distrust.message}</p>}
        </div>

        <div className="finding-section">
          <div className="detail-heading">
            <span className="detail-heading-icon amber"><Icon name="shieldAlert" size={15} /></span>
            CERTIFICATE FINDINGS
            <span className="finding-count">{findings.length}</span>
          </div>
          {findings.length ? (
            <ul className="finding-list">
              {findings.map((finding, index) => (
                <li key={`${finding.code || finding.title}-${index}`}>
                  <span className="finding-bullet" />
                  <div className="finding-copy">
                    <span>{finding.title}</span>
                    {finding.severity && <span className={`finding-severity ${finding.severity}`}>{finding.severity}</span>}
                    {finding.evidence && <small>{finding.evidence}</small>}
                    {finding.recommendation && <small>Recommendation: {finding.recommendation}</small>}
                  </div>
                </li>
              ))}
            </ul>
          ) : verified ? (
            <div className="clean-finding"><Icon name="check" size={15} /> No certificate security findings were reported.</div>
          ) : (
            <p className="muted-copy">{cert.error || "Certificate findings are unavailable."}</p>
          )}
        </div>

        <div className="scope-notice" style={{ margin: 15 }}>
          <Icon name="info" size={18} />
          <p style={{ fontSize: 13 }}>
            A verified TLS certificate confirms encrypted transport and certificate validation—not that the website itself is trustworthy. CT search coverage is partial; this service does not check OCSP/CRL revocation or maintain a separate known-distrust database.
          </p>
        </div>
      </section>
    </div>
  );
}
