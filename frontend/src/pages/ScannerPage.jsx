import React from "react";
import Icon from "../components/Icon.jsx";

export default function ScannerPage({ composer, scan, scanning, ScanResult }) {
  return (
    <div className="scanner-page">
      {composer}
      {scanning ? (
        <section className="panel scanner-empty scanner-loading" role="status" aria-live="polite">
          <span className="spinner" />
          <h2>Analyzing URL</h2>
          <p>Running heuristic checks and the machine-learning phishing classifier.</p>
        </section>
      ) : scan ? (
        <ScanResult scan={scan} />
      ) : (
        <section className="panel scanner-empty">
          <div className="empty-icon"><Icon name="shield" size={25} /></div>
          <h2>Ready to inspect a URL</h2>
          <p>Submit a website above to view its security status, risk score, and AI model probabilities.</p>
        </section>
      )}
    </div>
  );
}
