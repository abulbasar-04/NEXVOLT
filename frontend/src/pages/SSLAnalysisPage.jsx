import React from "react";
import Icon from "../components/Icon.jsx";

export default function SSLAnalysisPage({ scan, onNavigate, EmptyState }) {
  if (!scan) {
    return (
      <section className="panel full-panel">
        <EmptyState
          icon="lock"
          title="No URL analyzed"
          description="Run a URL scan to check whether the website address uses HTTPS transport."
          action={<>Scan a URL <Icon name="chevron" size={15} /></>}
          onAction={() => onNavigate("scanner")}
        />
      </section>
    );
  }

  const https = Boolean(scan.result.analysis?.uses_https);
  return (
    <div className="ssl-layout">
      <section className="panel ssl-hero-panel">
        <div className="ssl-hero-top">
          <div className={`ssl-large-icon ${https ? "good" : "attention"}`}><Icon name="lock" size={26} /></div>
          <span className={`verdict-pill ${https ? "safe" : "warning"}`}><span className="status-dot" />{https ? "HTTPS enabled" : "HTTP only"}</span>
        </div>
        <div className="section-kicker">TRANSPORT SECURITY</div>
        <h2>{https ? "Encrypted connection indicated" : "Connection is not encrypted"}</h2>
        <p className="ssl-host">{scan.result.url}</p>
        <div className="ssl-status-banner">
          <Icon name={https ? "check" : "info"} size={17} />
          <span>{https ? "The scanned URL uses the HTTPS scheme." : "The scanned URL uses HTTP. Data sent to this address may not be encrypted in transit."}</span>
        </div>
      </section>
      <section className="panel cert-panel">
        <div className="panel-header">
          <div><h2>Certificate details</h2><p>Certificate metadata from the scan</p></div>
          <span className="metadata-label">API SCOPE</span>
        </div>
        <div className="cert-details">
          <div><span>Transport scheme</span><strong>{scan.result.analysis?.scheme?.toUpperCase() || "Unknown"}</strong></div>
          <div><span>HTTPS in URL</span><strong className={https ? "text-good" : "text-warn"}>{https ? "Yes" : "No"}</strong></div>
          <div><span>Certificate issuer</span><strong className="unavailable-value">Not provided by API</strong></div>
          <div><span>Valid from / expires</span><strong className="unavailable-value">Not provided by API</strong></div>
          <div><span>Hostname validation</span><strong className="unavailable-value">Not checked by API</strong></div>
        </div>
        <div className="scope-notice">
          <Icon name="info" size={16} />
          <p>The current FastAPI scan endpoint reports the URL scheme, but does not connect to the host to validate its TLS certificate. HTTPS status alone does not guarantee a site is trustworthy.</p>
        </div>
      </section>
    </div>
  );
}
