import React from "react";
import Icon from "../components/Icon.jsx";

export default function ThreatIntelligencePage({ scan, onNavigate, EmptyState, ThreatSummary }) {
  if (!scan) {
    return (
      <section className="panel full-panel">
        <EmptyState
          icon="activity"
          title="No intelligence to show yet"
          description="Threat intelligence is generated from real scan results and DNS lookups."
          action={<>Start a scan <Icon name="chevron" size={15} /></>}
          onAction={() => onNavigate("scanner")}
        />
      </section>
    );
  }

  return (
    <div className="intel-page">
      <section className="panel intel-main-panel">
        <div className="panel-header">
          <div><h2>Threat intelligence</h2><p>Signals calculated for the most recently viewed URL.</p></div>
          <span className="intel-source"><Icon name="spark" size={13} /> LOCAL SCAN DATA</span>
        </div>
        <ThreatSummary scan={scan} />
      </section>
      <section className="panel intel-findings-panel">
        <div className="panel-header">
          <div><h2>URLhaus intelligence</h2><p>Threat feed and locally detected URL signals</p></div>
          <span className="metadata-label">FEED STATUS</span>
        </div>
        <div className="urlhaus-status">
          <span className="urlhaus-icon"><Icon name="globe" size={19} /></span>
          <div>
            <strong>URLhaus lookup is not connected</strong>
            <p>The current FastAPI backend does not expose a URLhaus feed or lookup endpoint. No URLhaus match status is available for this URL.</p>
          </div>
        </div>
        <div className="urlhaus-target">
          <span>URL analyzed</span>
          <strong>{scan.result.url}</strong>
        </div>
        <div className="urlhaus-divider" />
        <div className="urlhaus-local-heading"><span className="detail-heading-icon amber"><Icon name="activity" size={15} /></span> AVAILABLE LOCAL SIGNALS</div>
        {scan.result.findings?.length
          ? <ul className="expanded-findings">{scan.result.findings.map((finding, index) => <li key={`${finding}-${index}`}><span className="finding-bullet" /><span>{finding}</span><Icon name="info" size={15} /></li>)}</ul>
          : <div className="clean-finding"><Icon name="check" size={15} /> No heuristic risk indicators were detected by the local scan.</div>}
        <p className="data-source-note">This assessment combines the backend's URL heuristics, ML prediction, and DNS results. URLhaus results require a backend integration and are not inferred here.</p>
      </section>
    </div>
  );
}
