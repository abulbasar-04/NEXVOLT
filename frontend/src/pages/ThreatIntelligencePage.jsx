import React from "react";
import Icon from "../components/Icon.jsx";

function readable(value) {
  if (value === null || value === undefined || value === "") return "Not available";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatTime(value) {
  if (!value) return "Not reported";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function sourceStatusLabel(status) {
  return {
    malicious: "Confirmed match",
    not_found: "No match",
    unavailable: "Unavailable",
    unknown: "Unknown",
    partial: "Partial coverage",
    invalid_input: "Invalid input",
    unverified: "Unverified reports",
    reviewed: "Community reviewed",
  }[status] || String(status || "unknown").replaceAll("_", " ");
}

function FeedCard({ sourceKey, feed }) {
  const details = feed.details || {};
  const matched = feed.status === "malicious" && feed.malicious === true;
  const statusClass = matched
    ? "danger"
    : feed.status === "not_found"
      ? "safe"
      : "warning";
  const category = feed.category || details.threat || null;

  return (
    <article className="panel intel-findings-panel">
      <div className="panel-header intel-readable-header">
        <div>
          <h2>{feed.source || sourceKey}</h2>
          <p>Source-specific threat lookup</p>
        </div>
        <span className="metadata-label">{sourceStatusLabel(feed.status)}</span>
      </div>

      <div className={`intel-feed-status ${statusClass}`}>
        <div className="intel-feed-icon">
          <Icon name={matched ? "alert-triangle" : "globe"} size={22} />
        </div>
        <div>
          <strong>{sourceStatusLabel(feed.status)}</strong>
          <p>
            {matched
              ? "This source returned a confirmed threat match."
              : feed.source === "Community reports" && feed.status === "unverified"
                ? "Community submissions are unverified and do not confirm malicious activity."
                : feed.source === "Community reports" && feed.status === "reviewed"
                  ? "Moderation is not proof of malicious activity; corroborate with independent sources."
              : feed.status === "not_found"
                ? "No matching indicator was returned by this source. This does not prove the URL is safe."
                : feed.error || "This source did not return a definitive result."}
          </p>
        </div>
      </div>

      <div className="intel-feed-details">
        <div className="intel-data-row">
          <span>Threat category</span>
          <strong>{category ? readable(category).replaceAll("_", " ") : "No category reported"}</strong>
        </div>
        <div className="intel-data-row">
          <span>Source confidence</span>
          <strong>{feed.confidence || "Not provided"}</strong>
        </div>
        {feed.confidence_note && (
          <div className="intel-data-row">
            <span>Confidence method</span>
            <strong>{feed.confidence_note}</strong>
          </div>
        )}
        <div className="intel-data-row">
          <span>Last checked</span>
          <strong>{formatTime(feed.checked_at)}</strong>
        </div>
        {feed.source === "Community reports" && (
          <>
            <div className="intel-data-row">
              <span>Community reports</span>
              <strong>{details.report_count || 0}</strong>
            </div>
            <div className="intel-data-row">
              <span>Distinct reporters</span>
              <strong>{details.distinct_reporters || 0}</strong>
            </div>
            <div className="intel-data-row">
              <span>Moderator-reviewed reporters</span>
              <strong>{details.reviewed_reporters || 0}</strong>
            </div>
            {details.categories && (
              <div className="intel-data-row">
                <span>Reported categories</span>
                <strong>
                  {Object.entries(details.categories)
                    .map(([name, count]) => `${name.replaceAll("_", " ")} (${count})`)
                    .join(", ") || "None"}
                </strong>
              </div>
            )}
          </>
        )}
        <div className="intel-data-row">
          <span>Source report date</span>
          <strong>{formatTime(feed.reported_at || details.date_added || details.submission_time)}</strong>
        </div>
        {details.threat && (
          <div className="intel-data-row">
            <span>Source threat type</span>
            <strong>{readable(details.threat)}</strong>
          </div>
        )}
        {details.target && (
          <div className="intel-data-row">
            <span>Target brand</span>
            <strong>{readable(details.target)}</strong>
          </div>
        )}
      </div>

      {Array.isArray(details.tags) && details.tags.length > 0 && (
        <div className="intel-tags-block">
          <span>SOURCE TAGS</span>
          <div className="dns-summary">
            {details.tags.map((tag, index) => (
              <span className="dns-tag" key={`${tag}-${index}`}>{tag}</span>
            ))}
          </div>
        </div>
      )}
    </article>
  );
}

export default function ThreatIntelligencePage({
  scan,
  onNavigate,
  EmptyState,
  ThreatSummary,
}) {
  if (!scan) {
    return (
      <section className="panel full-panel" style={{ padding: 30 }}>
        <EmptyState
          icon="activity"
          title="No intelligence to show yet"
          description="Threat intelligence is generated from real scan results."
          action="Start a scan"
          onAction={() => onNavigate("scanner")}
        />
      </section>
    );
  }

  const result = scan.result || {};
  const intelligence = result.threat_intelligence || {};
  const legacyUrlhaus = intelligence.urlhaus || {};
  const sources = intelligence.sources && Object.keys(intelligence.sources).length
    ? intelligence.sources
    : { urlhaus: legacyUrlhaus };
  const threatFindings = Array.isArray(intelligence.findings)
    ? intelligence.findings
    : [];
  const localFindings = Array.isArray(result.finding_details)
    ? result.finding_details.filter(
      (finding) => !String(finding.source || "")
        .split(",")
        .map((source) => source.trim())
        .some((source) => ["URLhaus", "PhishTank", "OpenPhish", "Threat intelligence", "Community reports"].includes(source)),
    )
    : [];
  const phishing = result.phishing_analysis || {};
  const website = result.website_analysis || {};
  const websiteFindings = Array.isArray(website.findings) ? website.findings : [];

  return (
    <div className="intel-page intel-readable">
      <section className="panel intel-main-panel">
        <div className="panel-header intel-readable-header">
          <div>
            <h2>Threat Intelligence</h2>
            <p>Independent source results for the analyzed URL. No-match results are not proof of safety.</p>
          </div>
          <span className="intel-source">
            <Icon name="spark" size={14} /> {sourceStatusLabel(intelligence.status)}
          </span>
        </div>

        <div className="intel-summary-wrap">
          <ThreatSummary scan={scan} />
        </div>

        <div className="intel-url-card">
          <span>URL ANALYZED</span>
          <strong>{readable(result.url)}</strong>
        </div>

        <div className="intel-data-grid">
          <div className="intel-data-row">
            <span>Threat intelligence status</span>
            <strong>{sourceStatusLabel(intelligence.status || legacyUrlhaus.status)}</strong>
          </div>
          <div className="intel-data-row">
            <span>Confirmed unique findings</span>
            <strong>{threatFindings.length}</strong>
          </div>
          <div className="intel-data-row">
            <span>Last aggregate check</span>
            <strong>{formatTime(intelligence.checked_at)}</strong>
          </div>
        </div>

        {threatFindings.length > 0 && (
          <>
            <div className="intel-section-title">
              <span className="detail-heading-icon amber">
                <Icon name="shieldAlert" size={16} />
              </span>
              CONFIRMED THREAT FINDINGS
            </div>
            <ul className="expanded-findings intel-findings-list">
              {threatFindings.map((finding) => (
                <li key={finding.id || `${finding.category}-${finding.title}`}>
                  <span className="finding-bullet" />
                  <span>
                    <strong>{finding.title}</strong>
                    <br />
                    Category: {readable(finding.category).replaceAll("_", " ")}
                    {" · "}Source: {(finding.sources || []).join(", ") || "Not reported"}
                    {" · "}Confidence: {finding.confidence || "Not provided"}
                    <br />
                    {finding.evidence}
                    {finding.recommendation && <><br />Recommendation: {finding.recommendation}</>}
                  </span>
                  <Icon name="info" size={16} />
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      {Object.entries(sources).map(([sourceKey, feed]) => (
        <FeedCard key={sourceKey} sourceKey={sourceKey} feed={feed || { status: "unknown" }} />
      ))}

      <section className="panel intel-findings-panel">
        <div className="panel-header intel-readable-header">
          <div>
            <h2>Additional Scan Signals</h2>
            <p>Local URL heuristic and website assessment findings; these are not threat-feed matches.</p>
          </div>
          <span className="metadata-label">LOCAL ANALYSIS</span>
        </div>

        <div className="intel-section-title">
          <span className="detail-heading-icon purple"><Icon name="activity" size={16} /></span>
          URL HEURISTIC FINDINGS
        </div>
        {localFindings.length > 0 ? (
          <ul className="expanded-findings intel-findings-list">
            {localFindings.map((finding, index) => (
              <li key={`${finding.code || finding.title}-${index}`}>
                <span className="finding-bullet" />
                <span>
                  <strong>{finding.title}</strong>
                  {finding.severity && <> · {finding.severity}</>}
                  {finding.evidence && <><br />{finding.evidence}</>}
                  {finding.recommendation && <><br />Recommendation: {finding.recommendation}</>}
                </span>
                <Icon name="info" size={16} />
              </li>
            ))}
          </ul>
        ) : (
          <div className="clean-finding intel-clean-finding">
            <Icon name="check" size={16} />
            No local risk-engine findings were reported.
          </div>
        )}

        <div className="intel-section-title">
          <span className="detail-heading-icon cyan"><Icon name="globe" size={16} /></span>
          WEBSITE ASSESSMENT
        </div>
        <div className="intel-data-grid">
          <div className="intel-data-row">
            <span>Assessment status</span>
            <strong>{readable(website.status)}</strong>
          </div>
          <div className="intel-data-row">
            <span>Observed findings</span>
            <strong>{websiteFindings.length}</strong>
          </div>
          <div className="intel-data-row">
            <span>Rule-based phishing score</span>
            <strong>{phishing.risk_score ?? "Not available"}</strong>
          </div>
        </div>
        {websiteFindings.length > 0 && (
          <ul className="expanded-findings intel-findings-list">
            {websiteFindings.map((finding, index) => (
              <li key={`website-${index}`}>
                <span className="finding-bullet" />
                <span>{readable(finding)}</span>
                <Icon name="info" size={16} />
              </li>
            ))}
          </ul>
        )}

        <p className="data-source-note intel-disclaimer">
          A match is attributed to the named feed. A no-match only describes that source's lookup; unavailable and unknown sources contribute no clean result. Feed confidence labels describe match evidence and are not calibrated probabilities.
        </p>
      </section>
    </div>
  );
}
