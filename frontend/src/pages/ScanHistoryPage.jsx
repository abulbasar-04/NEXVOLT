import React from "react";
import Icon from "../components/Icon.jsx";

export default function ScanHistoryPage({ history, onSelect, onNavigate, ScanTable, EmptyState }) {
  return (
    <section className="panel full-panel">
      <div className="panel-header">
        <div><h2>Scan history</h2><p>All URL analyses saved locally in this browser.</p></div>
        <span className="count-chip">{history.length} {history.length === 1 ? "scan" : "scans"}</span>
      </div>
      {history.length
        ? <ScanTable scans={history} onSelect={onSelect} />
        : <EmptyState
            icon="clock"
            title="Your history is clear"
            description="Run your first scan and results will be saved here on this device."
            action={<>Go to scanner <Icon name="chevron" size={15} /></>}
            onAction={() => onNavigate("scanner")}
          />}
    </section>
  );
}
