import React, { useEffect, useMemo, useRef, useState } from "react";
import { API_BASE_URL, getHealth, lookupDns, scanUrl } from "./api.js";
import Icon from "./components/Icon.jsx";
import Sidebar from "./components/Sidebar.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import ScannerPage from "./pages/ScannerPage.jsx";
import ScanHistoryPage from "./pages/ScanHistoryPage.jsx";
import ThreatIntelligencePage from "./pages/ThreatIntelligencePage.jsx";
import SSLAnalysisPage from "./pages/SSLAnalysisPage.jsx";

const HISTORY_KEY = "nexvolt.scan-history.v1";

function readHistory() {
  try {
    const stored = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(stored) ? stored : [];
  } catch (error) {
    console.warn("Could not read saved NEXVOLT scan history.", error);
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
  return getScanStatus(scan.result).tone !== "safe";
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
        <div className="user-avatar" title="NEXVOLT workspace">NV</div>
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

function RiskScore({ score, verdict, tone: statusTone }) {
  const tone = statusTone || getVerdictTone(verdict);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const progress = circumference * (1 - Math.min(Math.max(score, 0), 100) / 100);
  return (
    <div className={`risk-score ${tone}`}>
      <svg viewBox="0 0 128 128" className="risk-ring" role="img" aria-label={`Risk score ${score} out of 100`}>
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
      <div className="risk-score-number"><strong>{score}</strong><span>/100</span></div>
      <span className="risk-score-label">RISK SCORE</span>
    </div>
  );
}

function ScanResult({ scan }) {
  const result = scan.result;
  const status = getScanStatus(result);
  const tone = status.tone;
  const ml = result.ml_prediction || {};
  const analysis = result.analysis || {};
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
        <span className="timestamp"><Icon name="clock" size={14} />{formatDate(scan.scannedAt)}</span>
      </div>
      <div className="result-main">
        <RiskScore score={result.risk_score} verdict={result.verdict} tone={tone} />
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
        <div className="detail-heading"><span className="detail-heading-icon amber"><Icon name="activity" size={15} /></span> SCAN FINDINGS <span className="finding-count">{result.findings?.length || 0}</span></div>
        {result.findings?.length ? (
          <ul className="finding-list">{result.findings.map((finding, index) => (
            <li key={`${finding}-${index}`}><span className="finding-bullet" />{finding}</li>
          ))}</ul>
        ) : <div className="clean-finding"><Icon name="check" size={15} /> No heuristic risk indicators were detected.</div>}
      </div>
      <div className="transport-strip">
        <span className={`transport-icon ${analysis.uses_https ? "good" : "attention"}`}><Icon name="lock" size={15} /></span>
        <div><strong>{analysis.uses_https ? "HTTPS transport detected" : "Unencrypted HTTP connection"}</strong><span>{analysis.uses_https ? "The URL uses HTTPS. Certificate issuer and expiration are not exposed by this API." : "This address does not use HTTPS."}</span></div>
        <span className={`transport-state ${analysis.uses_https ? "good" : "attention"}`}>{analysis.uses_https ? "HTTPS" : "HTTP"}</span>
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

function ScanTable({ scans, onSelect, compact = false }) {
  if (!scans.length) {
    return <EmptyState icon="clock" title="No scans yet" description="Your completed URL scans will appear here." />;
  }
  return (
    <div className="table-scroll">
      <table className="scan-table">
        <thead><tr><th>WEBSITE</th><th>VERDICT</th><th>RISK SCORE</th><th>SCANNED</th><th /></tr></thead>
        <tbody>
          {scans.slice(0, compact ? 4 : undefined).map((scan) => {
            const tone = getScanStatus(scan.result).tone;
            return (
              <tr key={scan.id} onClick={() => onSelect(scan)} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && onSelect(scan)}>
                <td><div className="table-domain"><span className="table-favicon"><Icon name="globe" size={14} /></span><span><strong>{scan.result.analysis?.domain || scan.result.url}</strong><small>{scan.result.url}</small></span></div></td>
                <td><span className={`table-verdict ${tone}`}><span className="status-dot" />{scan.result.verdict}</span></td>
                <td><span className={`table-score ${tone}`}>{scan.result.risk_score}<small>/100</small></span></td>
                <td className="table-date">{formatDate(scan.scannedAt)}</td>
                <td><Icon name="chevron" size={15} className="table-chevron" /></td>
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
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const selectedScan = useMemo(
    () => history.find((scan) => scan.id === selectedScanId) || history[0] || null,
    [history, selectedScanId],
  );

  useEffect(() => {
    let active = true;
    getHealth().then(
      (data) => active && setApiOnline(data.status === "healthy"),
      () => active && setApiOnline(false),
    );
    const refresh = window.setInterval(() => {
      getHealth().then(
        (data) => active && setApiOnline(data.status === "healthy"),
        () => active && setApiOnline(false),
      );
    }, 30_000);
    return () => { active = false; window.clearInterval(refresh); };
  }, []);

  function persistHistory(nextHistory) {
    historyRef.current = nextHistory;
    setHistory(nextHistory);
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(nextHistory));
    } catch (error) {
      console.error("Could not save NEXVOLT scan history.", error);
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

  const pageInfo = {
    overview: ["Overview", "Monitor website trust and analyze suspicious URLs."],
    scanner: ["URL scanner", "Analyze a URL and inspect phishing and security signals."],
    history: ["Scan history", "Review previous URL analysis results."],
    intelligence: ["Threat intelligence", "Understand the signals behind your URL risk assessment."],
    ssl: ["SSL certificate analysis", "Review transport security details from your latest scan."],
  }[activeView];

  return (
    <div className="app-shell">
      {mobileNavOpen && <button className="mobile-backdrop" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation" />}
      <div className={`sidebar-container ${mobileNavOpen ? "open" : ""}`}>
        <Sidebar activeView={activeView} onNavigate={setActiveView} apiOnline={apiOnline} onClose={() => setMobileNavOpen(false)} />
      </div>
      <main className="main-content">
        <SidebarHeader title={pageInfo[0]} subtitle={pageInfo[1]} onMenu={() => setMobileNavOpen(true)} />
        <div className="page-content">
          <div className="backend-banner">
            <span className={`status-dot ${apiOnline ? "online" : "offline"}`} />
            <span>{apiOnline ? "Connected to NEXVOLT API" : "Backend not responding"}</span>
            <span className="backend-url">{API_BASE_URL}</span>
            {!apiOnline && <span className="backend-help">Start the FastAPI server to scan URLs.</span>}
          </div>
          {activeView === "overview" && (
            <Dashboard
              history={history}
              currentScan={selectedScan}
              onSelect={selectScan}
              onNavigate={setActiveView}
              isRiskyScan={isRiskyScan}
              MetricCard={MetricCard}
              ScanTable={ScanTable}
              ThreatSummary={ThreatSummary}
              EmptyState={EmptyState}
              ScanResult={ScanResult}
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
              ScanResult={ScanResult}
            />
          )}
          {activeView === "history" && <ScanHistoryPage history={history} onSelect={selectScan} onNavigate={setActiveView} ScanTable={ScanTable} EmptyState={EmptyState} />}
          {activeView === "intelligence" && <ThreatIntelligencePage scan={selectedScan} onNavigate={setActiveView} EmptyState={EmptyState} ThreatSummary={ThreatSummary} />}
          {activeView === "ssl" && <SSLAnalysisPage scan={selectedScan} onNavigate={setActiveView} EmptyState={EmptyState} />}
          <footer className="page-footer"><span>NEXVOLT SECURITY INTELLIGENCE</span><span>Scan results are preliminary assessments, not guarantees of safety.</span></footer>
        </div>
      </main>
      <div className="toast-aria" aria-live="polite" />
    </div>
  );
}
