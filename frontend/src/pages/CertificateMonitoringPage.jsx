import React, { useCallback, useEffect, useState } from "react";
import {
  addCertificateMonitor,
  checkCertificateMonitor,
  getCertificateMonitorAlerts,
  getCertificateMonitorHistory,
  getCertificateMonitors,
  removeCertificateMonitor,
} from "../api.js";
import Icon from "../components/Icon.jsx";

function formatDate(value) {
  if (!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatIssuer(value) {
  if (!value || typeof value !== "object") return value || "Not available";
  return Object.values(value).filter(Boolean).join(", ") || "Not available";
}

function readable(value) {
  return String(value || "unknown").replaceAll("_", " ");
}

function ObservationSummary({ observation }) {
  if (!observation) {
    return <p className="muted-copy">No certificate observation has been recorded.</p>;
  }
  const sans = Array.isArray(observation.san_domains) ? observation.san_domains : [];
  return (
    <>
      <div className="monitor-data-grid">
        <div className="intel-data-row"><span>Certificate status</span><strong>{readable(observation.status)}</strong></div>
        <div className="intel-data-row"><span>Observation</span><strong>{readable(observation.change_type)}</strong></div>
        <div className="intel-data-row"><span>Issuer</span><strong>{formatIssuer(observation.issuer)}</strong></div>
        <div className="intel-data-row"><span>Serial number</span><strong>{observation.serial_number || "Not available"}</strong></div>
        <div className="intel-data-row"><span>Public key</span><strong>
          {observation.public_key?.algorithm
            ? `${observation.public_key.algorithm}${observation.public_key.key_size ? ` · ${observation.public_key.key_size} bits` : ""}`
            : "Not available"}
        </strong></div>
        <div className="intel-data-row"><span>Valid from</span><strong>{formatDate(observation.not_before)}</strong></div>
        <div className="intel-data-row"><span>Expires</span><strong>{formatDate(observation.expires_at)}</strong></div>
        <div className="intel-data-row monitor-fingerprint">
          <span>SHA-256 fingerprint</span>
          <strong>{observation.sha256_fingerprint || "Not available"}</strong>
        </div>
      </div>
      <div className="monitor-san-list">
        <span>SUBJECT ALTERNATIVE NAMES</span>
        {sans.length
          ? <div className="dns-summary">{sans.map((san, index) => {
              const label = typeof san === "string" ? san : `${san.type || "Name"}: ${san.value || "Not available"}`;
              return <span className="dns-tag" key={`${label}-${index}`}>{label}</span>;
            })}</div>
          : <p className="muted-copy">No SAN names were observed.</p>}
      </div>
    </>
  );
}

function AlertCard({ alert }) {
  const isRenewal = alert.change_type === "renewal";
  return (
    <article className={`monitor-alert ${isRenewal ? "renewal" : "potential"}`}>
      <div className="monitor-alert-heading">
        <span className="detail-heading-icon"><Icon name={isRenewal ? "activity" : "shieldAlert"} size={16} /></span>
        <div>
          <strong>{alert.domain}</strong>
          <span>{isRenewal ? "Certificate renewal observed" : "Certificate change needs review"}</span>
        </div>
        <span className={`finding-severity ${alert.severity || "medium"}`}>{alert.severity || "medium"}</span>
      </div>
      <div className="monitor-alert-meta">
        <span>{readable(alert.status)} · detected {formatDate(alert.detected_at)}</span>
      </div>
      <ul className="monitor-evidence">
        {(alert.evidence || []).map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
      </ul>
      {alert.recommendation && <p className="monitor-recommendation"><strong>Recommendation:</strong> {alert.recommendation}</p>}
      <p className="monitor-disclaimer">A certificate change is not, by itself, evidence that a site is malicious.</p>
    </article>
  );
}

export default function CertificateMonitoringPage() {
  const [domains, setDomains] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [intervalSeconds, setIntervalSeconds] = useState(null);
  const [domainInput, setDomainInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [historyById, setHistoryById] = useState({});
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const refresh = useCallback(async (isActive = () => true) => {
    const [monitorData, alertData] = await Promise.all([
      getCertificateMonitors(),
      getCertificateMonitorAlerts(),
    ]);
    if (!isActive()) return;
    setDomains(Array.isArray(monitorData.domains) ? monitorData.domains : []);
    setAlerts(Array.isArray(alertData.alerts) ? alertData.alerts : []);
    setIntervalSeconds(monitorData.interval_seconds);
  }, []);

  useEffect(() => {
    let active = true;
    const load = () => refresh(() => active)
      .catch((requestError) => active && setError(requestError.message))
      .finally(() => active && setLoading(false));
    load();
    const timer = window.setInterval(load, 60_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [refresh]);

  async function handleAdd(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    setSaving(true);
    try {
      const result = await addCertificateMonitor(domainInput);
      setDomainInput("");
      setMessage(result.created
        ? `Monitoring enabled for ${result.domain.domain}. The first check establishes a baseline.`
        : `${result.domain.domain} is already monitored.`);
      await refresh();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSaving(false);
    }
  }

  async function handleCheck(domain) {
    setError("");
    setMessage("");
    setBusyId(domain.id);
    try {
      const observation = await checkCertificateMonitor(domain.id);
      setMessage(`${domain.domain}: ${readable(observation.change_type)} check recorded.`);
      await refresh();
      if (expandedId === domain.id) {
        const history = await getCertificateMonitorHistory(domain.id);
        setHistoryById((current) => ({ ...current, [domain.id]: history.observations }));
      }
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusyId(null);
    }
  }

  async function handleRemove(domain) {
    if (!window.confirm(`Stop monitoring ${domain.domain}? Its stored certificate history will be retained but hidden.`)) return;
    setError("");
    setMessage("");
    setBusyId(domain.id);
    try {
      await removeCertificateMonitor(domain.id);
      if (expandedId === domain.id) setExpandedId(null);
      setMessage(`Monitoring stopped for ${domain.domain}.`);
      await refresh();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusyId(null);
    }
  }

  async function toggleHistory(domain) {
    if (expandedId === domain.id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(domain.id);
    if (historyById[domain.id]) return;
    try {
      const history = await getCertificateMonitorHistory(domain.id);
      setHistoryById((current) => ({ ...current, [domain.id]: history.observations }));
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  const intervalLabel = intervalSeconds !== null && Number.isFinite(Number(intervalSeconds))
    ? `${Math.round(Number(intervalSeconds) / 3600 * 10) / 10} hours`
    : "configured interval";

  return (
    <div className="monitor-page">
      <section className="panel monitor-intro">
        <div className="panel-header">
          <div>
            <h2>Certificate change monitoring</h2>
            <p>Track real TLS certificate observations over time for domains you monitor.</p>
          </div>
          <span className="metadata-label"><Icon name="lock" size={13} /> SCHEDULED CHECKS</span>
        </div>
        <p className="monitor-schedule-note">
          Automatic checks run every {intervalLabel}. Adding a domain triggers an immediate check; its first available certificate is recorded as a baseline, not an alert.
        </p>
        <form className="monitor-add-form" onSubmit={handleAdd}>
          <Icon name="globe" size={18} />
          <input
            type="text"
            value={domainInput}
            onChange={(event) => setDomainInput(event.target.value)}
            placeholder="example.com"
            aria-label="Domain to monitor"
            autoComplete="url"
            required
            disabled={saving}
          />
          <button className="scan-button" type="submit" disabled={saving || !domainInput.trim()}>
            {saving ? <span className="spinner" /> : <Icon name="check" size={16} />}
            <span>{saving ? "Checking" : "Add domain"}</span>
          </button>
        </form>
        {error && <div className="inline-error" role="alert"><Icon name="shieldAlert" size={16} />{error}</div>}
        {message && <div className="monitor-feedback" role="status"><Icon name="info" size={16} />{message}</div>}
      </section>

      <section className="panel monitor-list-panel">
        <div className="panel-header">
          <div><h2>Monitored domains</h2><p>Latest observed certificate and fingerprint baseline</p></div>
          <span className="count-chip">{domains.length} {domains.length === 1 ? "domain" : "domains"}</span>
        </div>
        {loading ? (
          <div className="monitor-loading"><span className="spinner" /> Loading monitored domains…</div>
        ) : domains.length ? (
          <div className="monitor-domain-list">
            {domains.map((domain) => {
              const latest = domain.latest_observation;
              const history = historyById[domain.id];
              return (
                <article className="monitor-domain-card" key={domain.id}>
                  <div className="monitor-domain-heading">
                    <div className="monitor-domain-title">
                      <span className={`status-dot ${latest?.sha256_fingerprint ? "online" : "offline"}`} />
                      <div><h3>{domain.domain}</h3><span>Last checked {formatDate(domain.last_checked_at)}</span></div>
                    </div>
                    <div className="monitor-actions">
                      <button className="text-button compact" onClick={() => handleCheck(domain)} disabled={busyId === domain.id}>
                        {busyId === domain.id ? <span className="spinner" /> : <Icon name="activity" size={15} />}
                        Check now
                      </button>
                      <button className="text-button compact" onClick={() => toggleHistory(domain)}>
                        <Icon name="clock" size={15} />{expandedId === domain.id ? "Hide history" : "History"}
                      </button>
                      <button className="icon-button monitor-remove" onClick={() => handleRemove(domain)} disabled={busyId === domain.id} aria-label={`Stop monitoring ${domain.domain}`}>
                        <Icon name="close" size={15} />
                      </button>
                    </div>
                  </div>
                  {latest ? <ObservationSummary observation={latest} /> : (
                    <div className="monitor-empty-observation">
                      <Icon name="info" size={16} />
                      No certificate baseline was recorded. The domain may have been unavailable during its first check.
                    </div>
                  )}
                  {expandedId === domain.id && (
                    <div className="monitor-history">
                      <div className="detail-heading"><span className="detail-heading-icon purple"><Icon name="clock" size={15} /></span>OBSERVATION HISTORY</div>
                      {!history ? <div className="monitor-loading"><span className="spinner" /> Loading history…</div> : history.length ? (
                        <div className="monitor-history-list">
                          {history.map((item) => (
                            <div className="monitor-history-row" key={item.id}>
                              <span className="monitor-history-date">{formatDate(item.observed_at)}</span>
                              <strong>{readable(item.change_type)}</strong>
                              <span>{readable(item.status)}</span>
                              {item.severity && <span className={`finding-severity ${item.severity}`}>{item.severity}</span>}
                              {item.evidence?.[0] && <small>{item.evidence[0]}</small>}
                            </div>
                          ))}
                        </div>
                      ) : <p className="muted-copy">No observations recorded.</p>}
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        ) : (
          <div className="monitor-empty-state">
            <span className="monitor-empty-icon"><Icon name="lock" size={22} /></span>
            <h3>No monitored domains yet</h3>
            <p>Add a domain to establish a real certificate baseline and start tracking changes.</p>
          </div>
        )}
      </section>

      <section className="panel monitor-alerts-panel">
        <div className="panel-header">
          <div><h2>Certificate change alerts</h2><p>New fingerprints compared with earlier observations</p></div>
          <span className="count-chip">{alerts.length} {alerts.length === 1 ? "alert" : "alerts"}</span>
        </div>
        {alerts.length ? alerts.map((alert) => <AlertCard key={alert.id} alert={alert} />) : (
          <div className="clean-finding"><Icon name="check" size={15} /> No certificate changes have been detected in the monitored domains.</div>
        )}
        <p className="monitor-disclaimer">Changes are evidence for review, not a verdict that a domain or certificate is malicious.</p>
      </section>
    </div>
  );
}
