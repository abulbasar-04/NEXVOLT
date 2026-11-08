import React, { useEffect, useState } from "react";
import Icon from "../components/Icon.jsx";
import {
  getAdminCommunityReports,
  getCommunityReports,
  getVerifiedCommunityReports,
  initializeCommunityReportSession,
  moderateCommunityReport,
  submitCommunityReport,
} from "../api.js";

const CATEGORIES = [
  "phishing",
  "malware",
  "scam",
  "impersonation",
  "suspicious redirect",
  "other",
];

function formatTime(value) {
  if (!value) return "Time not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function statusTone(status) {
  if (status === "approved") return "approved";
  if (status === "rejected") return "rejected";
  if (status === "resolved") return "resolved";
  return "pending";
}

function ReportCard({ report, admin = false, onModerate, busy }) {
  return (
    <article className="community-report-card">
      <div className="community-report-topline">
        <span className={`community-report-status ${statusTone(report.status)}`}>
          <span className="status-dot" />
          {report.status.replaceAll("_", " ")}
        </span>
        <time>{formatTime(report.submitted_at)}</time>
      </div>
      <div className="community-report-url">{report.url}</div>
      <div className="community-report-meta">
        <span className="community-category">{report.category}</span>
        <span>{report.report_count} report{report.report_count === 1 ? "" : "s"}</span>
        <span>{report.distinct_reporters} distinct reporter{report.distinct_reporters === 1 ? "" : "s"}</span>
      </div>
      {admin && (
        <>
          {report.evidence && (
            <div className="community-evidence">
              <span>SUBMITTED EVIDENCE</span>
              <p>{report.evidence}</p>
            </div>
          )}
          {report.moderation_note && (
            <div className="community-evidence">
              <span>MODERATION NOTE</span>
              <p>{report.moderation_note}</p>
            </div>
          )}
          {report.status === "pending" && (
            <div className="community-moderation-actions">
              <button type="button" disabled={busy} onClick={() => onModerate(report.id, "approved")}>
                Approve
              </button>
              <button type="button" disabled={busy} onClick={() => onModerate(report.id, "rejected")}>
                Reject
              </button>
              <button type="button" disabled={busy} onClick={() => onModerate(report.id, "resolved")}>
                Resolve
              </button>
            </div>
          )}
          {report.status === "approved" && (
            <div className="community-moderation-actions">
              <button type="button" disabled={busy} onClick={() => onModerate(report.id, "resolved")}>
                Mark resolved
              </button>
            </div>
          )}
        </>
      )}
    </article>
  );
}

export default function CommunityReportsPage() {
  const [reports, setReports] = useState([]);
  const [verifiedReports, setVerifiedReports] = useState([]);
  const [verifiedLoading, setVerifiedLoading] = useState(true);
  const [verifiedError, setVerifiedError] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [form, setForm] = useState({ url: "", category: "phishing", evidence: "" });
  const [adminOpen, setAdminOpen] = useState(false);
  const [adminToken, setAdminToken] = useState("");
  const [adminReports, setAdminReports] = useState([]);
  const [adminError, setAdminError] = useState("");
  const [adminBusy, setAdminBusy] = useState(false);
  const [moderationNote, setModerationNote] = useState("");

  async function loadReports() {
    const data = await getCommunityReports({ limit: 50 });
    setReports(data.reports || []);
  }

  async function loadVerifiedReports() {
    setVerifiedError("");
    setVerifiedLoading(true);
    try {
      const data = await getVerifiedCommunityReports({ limit: 50 });
      setVerifiedReports(data.reports || []);
    } catch (requestError) {
      setVerifiedError(requestError.message);
    } finally {
      setVerifiedLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    async function initialize() {
      try {
        await initializeCommunityReportSession();
        const data = await getCommunityReports({ limit: 50 });
        if (active) setReports(data.reports || []);
      } catch (requestError) {
        if (active) setError(requestError.message);
      } finally {
        if (active) setLoading(false);
      }
    }
    initialize();
    return () => { active = false; };
  }, []);

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    setSubmitting(true);
    try {
      const result = await submitCommunityReport(form);
      setMessage(result.message);
      setForm({ url: "", category: "phishing", evidence: "" });
      await loadReports();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSubmitting(false);
    }
  }

  async function loadModerationQueue(event) {
    event?.preventDefault();
    setAdminError("");
    if (!adminToken.trim()) {
      setAdminError("Enter the administrator token configured on the backend.");
      return;
    }
    setAdminBusy(true);
    try {
      const data = await getAdminCommunityReports(adminToken.trim());
      setAdminReports(data.reports || []);
    } catch (requestError) {
      setAdminError(requestError.message);
      setAdminReports([]);
    } finally {
      setAdminBusy(false);
    }
  }

  async function handleModerate(reportId, status) {
    setAdminError("");
    setAdminBusy(true);
    try {
      await moderateCommunityReport(reportId, adminToken.trim(), status, moderationNote);
      const [adminData, publicData] = await Promise.all([
        getAdminCommunityReports(adminToken.trim()),
        getCommunityReports({ limit: 50 }),
      ]);
      setAdminReports(adminData.reports || []);
      setReports(publicData.reports || []);
      setModerationNote("");
    } catch (requestError) {
      setAdminError(requestError.message);
    } finally {
      setAdminBusy(false);
    }
  }

  return (
    <div className="community-page">
      <section className="panel community-submit-panel">
        <div className="panel-header intel-readable-header">
          <div>
            <h2>Submit a threat report</h2>
            <p>Share a suspicious URL and evidence for community review.</p>
          </div>
          <span className="intel-source"><Icon name="shieldAlert" size={15} /> COMMUNITY SIGNAL</span>
        </div>
        <form className="community-report-form" onSubmit={handleSubmit}>
          <label>
            Suspicious URL
            <input
              type="url"
              required
              maxLength={2048}
              placeholder="https://example.com/suspicious-page"
              value={form.url}
              onChange={(event) => setForm((current) => ({ ...current, url: event.target.value }))}
            />
          </label>
          <label>
            Category
            <select
              value={form.category}
              onChange={(event) => setForm((current) => ({ ...current, category: event.target.value }))}
            >
              {CATEGORIES.map((category) => (
                <option key={category} value={category}>{category}</option>
              ))}
            </select>
          </label>
          <label className="community-evidence-input">
            Evidence <span>(optional, 2,000 characters maximum)</span>
            <textarea
              maxLength={2000}
              rows={4}
              placeholder="Describe what you observed. Do not include personal or account information."
              value={form.evidence}
              onChange={(event) => setForm((current) => ({ ...current, evidence: event.target.value }))}
            />
          </label>
          {error && <div className="inline-error" role="alert"><Icon name="shieldAlert" size={15} />{error}</div>}
          {message && <div className="community-success" role="status"><Icon name="check" size={15} />{message}</div>}
          <div className="community-submit-footer">
            <p>Reports are pseudonymous and unverified until reviewed. A single report never confirms a threat.</p>
            <button type="submit" className="scan-button" disabled={submitting}>
              {submitting ? <span className="spinner" /> : <Icon name="send" size={15} />}
              {submitting ? "Submitting" : "Submit report"}
            </button>
          </div>
        </form>
      </section>

      <section className="panel community-verified-panel">
        <div className="panel-header intel-readable-header">
          <div>
            <h2><Icon name="shieldCheck" size={18} /> Verified Threat Feed</h2>
            <p>Threat reports reviewed and approved by an administrator.</p>
          </div>
          <div className="community-verified-heading-actions">
            <span className="community-verified-badge">ADMIN REVIEWED</span>
            <button type="button" className="text-button" onClick={loadVerifiedReports} disabled={verifiedLoading}>
              {verifiedLoading ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </div>
        <div className="community-feed-list">
          {verifiedLoading ? (
            <div className="community-empty"><span className="spinner" /> Loading verified threats…</div>
          ) : verifiedError ? (
            <div className="inline-error" role="alert">{verifiedError}</div>
          ) : verifiedReports.length ? (
            verifiedReports.map((report) => (
              <article className="community-report-card community-verified-card" key={report.id}>
                <div className="community-report-topline">
                  <span className="community-report-status approved"><span className="status-dot" /> Admin approved</span>
                  <time>{formatTime(report.submitted_at)}</time>
                </div>
                <div className="community-report-url">{report.url}</div>
                <div className="community-report-meta">
                  <span className="community-category">{report.category}</span>
                  <span>{report.report_count} approved report{report.report_count === 1 ? "" : "s"}</span>
                  <span>{report.distinct_reporters} distinct reporter{report.distinct_reporters === 1 ? "" : "s"}</span>
                </div>
              </article>
            ))
          ) : (
            <div className="community-empty">No administrator-approved threats yet.</div>
          )}
        </div>
        <p className="community-disclaimer">
          Admin approval indicates moderation review, not definitive proof of malicious activity. Verify with independent threat-intelligence sources before blocking or taking action.
        </p>
      </section>

      <section className="panel community-feed-panel">
        <div className="panel-header intel-readable-header">
          <div>
            <h2>Community report feed</h2>
            <p>Public summaries omit evidence and reporter identifiers.</p>
          </div>
          <span className="metadata-label">{reports.length} RECENT REPORTS</span>
        </div>
        <div className="community-feed-list">
          {loading ? (
            <div className="community-empty"><span className="spinner" /> Loading reports…</div>
          ) : reports.length ? (
            reports.map((report) => <ReportCard key={report.id} report={report} />)
          ) : (
            <div className="community-empty">No community reports yet.</div>
          )}
        </div>
        <p className="community-disclaimer">
          Community reports are user-submitted signals, not proof of malicious activity. Confirm indicators with independent sources before taking action.
        </p>
      </section>

      <section className="panel community-admin-panel">
        <div className="panel-header intel-readable-header">
          <div>
            <h2>Administrator moderation</h2>
            <p>Moderation requires a backend-configured administrator token.</p>
          </div>
          <button type="button" className="text-button" onClick={() => setAdminOpen((open) => !open)}>
            {adminOpen ? "Hide queue" : "Open moderation"}
            <Icon name="chevron" size={15} />
          </button>
        </div>
        {adminOpen && (
          <div className="community-admin-content">
            <form className="community-admin-auth" onSubmit={loadModerationQueue}>
              <label>
                Administrator token
                <input
                  type="password"
                  autoComplete="off"
                  value={adminToken}
                  onChange={(event) => setAdminToken(event.target.value)}
                  placeholder="Token stays in this page session"
                />
              </label>
              <button type="submit" className="text-button" disabled={adminBusy}>Load queue</button>
            </form>
            {adminError && <div className="inline-error" role="alert">{adminError}</div>}
            {adminReports.length > 0 && (
              <>
                <label className="community-note-input">
                  Moderation note (optional)
                  <input
                    maxLength={500}
                    value={moderationNote}
                    onChange={(event) => setModerationNote(event.target.value)}
                    placeholder="Internal note visible only to administrators"
                  />
                </label>
                <div className="community-feed-list">
                  {adminReports.map((report) => (
                    <ReportCard
                      key={report.id}
                      report={report}
                      admin
                      busy={adminBusy}
                      onModerate={handleModerate}
                    />
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
