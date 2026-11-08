import React from "react";
import Icon from "../components/Icon.jsx";
import { hasUnifiedRiskScore } from "../utils/riskScore.js";

export default function Dashboard({
  history,
  currentScan,
  composer,
  onSelect,
  onReport,
  onViewReport,
  onNavigate,
  isRiskyScan,
  MetricCard,
  ScanTable,
  ThreatSummary,
  EmptyState,
  ScanResult,
}) {
  const scoredHistory = history.filter((scan) => hasUnifiedRiskScore(scan.result));
  const riskyCount = scoredHistory.filter(isRiskyScan).length;
  const lowRiskCount = scoredHistory.filter((scan) =>
    String(scan.result.risk_category || "").toLowerCase() === "low" &&
    Number.isFinite(scan.result.risk_score),
  ).length;
  const lowRiskRate = scoredHistory.length
    ? Math.round((lowRiskCount / scoredHistory.length) * 100)
    : null;
  const averageRisk = scoredHistory.length
    ? Math.round(scoredHistory.reduce((total, scan) => total + scan.result.risk_score, 0) / scoredHistory.length)
    : null;

  return (
    <>
      {composer}
      <div className="section-heading overview-metrics-heading">
        <div><h2>Security overview</h2><p>A live view of your website threat landscape.</p></div>
        <span className="live-tag"><span className="status-dot online" /> UPDATED LIVE</span>
      </div>
      <div className="metrics-grid">
        <MetricCard label="TOTAL SCANS" value={history.length} caption="Saved on this device" icon="search" tone="purple" />
        <MetricCard
          label="LOW-RISK RATE"
          value={lowRiskRate === null ? "—" : `${lowRiskRate}%`}
          caption={history.length
            ? `${lowRiskCount} low-risk of ${scoredHistory.length} scored scans${scoredHistory.length < history.length ? ` · ${history.length - scoredHistory.length} unknown` : ""}`
            : "Complete a scan to get started"}
          icon="shield"
          tone="cyan"
        />
        <MetricCard label="THREATS FOUND" value={riskyCount} caption="Suspicious or dangerous URLs" icon="shieldAlert" tone="amber" />
        <MetricCard label="AVG. RISK SCORE" value={averageRisk === null ? "—" : `${averageRisk}/100`} caption={scoredHistory.length ? "Across scored URLs only" : "No risk scores available"} icon="activity" tone="pink" />
      </div>
      <div className="content-grid">
        <div className="panel recent-panel">
          <div className="panel-header">
            <div><h2>Recent scans</h2><p>Your latest URL analysis results</p></div>
            {history.length > 4 && <button className="text-button compact" onClick={() => onNavigate("history")}>View all <Icon name="chevron" size={14} /></button>}
          </div>
          <ScanTable scans={history} onSelect={onSelect} onReport={onReport} compact />
        </div>
        <div className="panel intelligence-panel">
          <div className="panel-header">
            <div><h2>Threat intelligence</h2><p>Signals from the latest scan</p></div>
            <span className="panel-live-mark"><span className="status-dot online" /></span>
          </div>
          {currentScan
            ? <ThreatSummary scan={currentScan} />
            : <EmptyState icon="activity" title="Intelligence starts here" description="Scan a URL to see its ML prediction, findings, and DNS record summary." />}
        </div>
      </div>
      <section className="panel dashboard-monitor-cta">
        <div className="monitor-cta-icon"><Icon name="lock" size={18} /></div>
        <div className="monitor-cta-copy">
          <h2>Monitor certificate changes</h2>
          <p>Establish certificate baselines and review issuer, fingerprint, validity, and SAN changes over time.</p>
        </div>
        <button className="text-button compact" onClick={() => onNavigate("certificate-monitoring")}>
          Open monitoring <Icon name="chevron" size={14} />
        </button>
      </section>
      <section className="panel dashboard-monitor-cta dashboard-trust-cta">
        <div className="monitor-cta-icon"><Icon name="target" size={18} /></div>
        <div className="monitor-cta-copy">
          <h2>Review the unified trust assessment</h2>
          <p>Inspect component coverage, source results, important findings, evidence, and remediation guidance.</p>
        </div>
        <button className="text-button compact" onClick={() => onNavigate("trust")}>
          Open trust dashboard <Icon name="chevron" size={14} />
        </button>
      </section>
      {currentScan && (
        <div className="dashboard-latest-result">
          <div className="section-heading">
            <div><h2>Latest scan details</h2><p>Security assessment and model output for your most recent URL.</p></div>
            <button className="text-button compact" onClick={() => onNavigate("scanner")}>Open scanner <Icon name="chevron" size={14} /></button>
          </div>
          <ScanResult scan={currentScan} onViewReport={onViewReport} />
        </div>
      )}
    </>
  );
}
