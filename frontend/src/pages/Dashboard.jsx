import React from "react";
import Icon from "../components/Icon.jsx";

export default function Dashboard({
  history,
  currentScan,
  composer,
  onSelect,
  onNavigate,
  isRiskyScan,
  MetricCard,
  ScanTable,
  ThreatSummary,
  EmptyState,
  ScanResult,
}) {
  const riskyCount = history.filter(isRiskyScan).length;
  const safeRate = history.length
    ? Math.round(((history.length - riskyCount) / history.length) * 100)
    : null;
  const averageRisk = history.length
    ? Math.round(history.reduce((total, scan) => total + scan.result.risk_score, 0) / history.length)
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
        <MetricCard label="SAFE RATE" value={safeRate === null ? "—" : `${safeRate}%`} caption={history.length ? `${history.length - riskyCount} safe of ${history.length} scans` : "Complete a scan to get started"} icon="shield" tone="cyan" />
        <MetricCard label="THREATS FOUND" value={riskyCount} caption="Suspicious or dangerous URLs" icon="shieldAlert" tone="amber" />
        <MetricCard label="AVG. RISK SCORE" value={averageRisk === null ? "—" : `${averageRisk}/100`} caption="Across your scanned URLs" icon="activity" tone="pink" />
      </div>
      <div className="content-grid">
        <div className="panel recent-panel">
          <div className="panel-header">
            <div><h2>Recent scans</h2><p>Your latest URL analysis results</p></div>
            {history.length > 4 && <button className="text-button compact" onClick={() => onNavigate("history")}>View all <Icon name="chevron" size={14} /></button>}
          </div>
          <ScanTable scans={history} onSelect={onSelect} compact />
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
      {currentScan && (
        <div className="dashboard-latest-result">
          <div className="section-heading">
            <div><h2>Latest scan details</h2><p>Security assessment and model output for your most recent URL.</p></div>
            <button className="text-button compact" onClick={() => onNavigate("scanner")}>Open scanner <Icon name="chevron" size={14} /></button>
          </div>
          <ScanResult scan={currentScan} />
        </div>
      )}
    </>
  );
}
