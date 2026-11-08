import React from "react";
import Icon from "./Icon.jsx";

const navigation = [
  { id: "overview", label: "Dashboard", icon: "grid" },
  { id: "scanner", label: "URL scanner", icon: "search" },
  { id: "history", label: "Scan history", icon: "clock" },
  { id: "intelligence", label: "Threat intelligence", icon: "activity" },
  { id: "ssl", label: "SSL certificate analysis", icon: "lock" },
];

export default function Sidebar({ activeView, onNavigate, apiOnline, onClose }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark"><Icon name="activity" size={21} strokeWidth={2.2} /></div>
        <div className="brand-copy">
          <span className="brand-name">NEXVOLT</span>
          <span className="brand-caption">WEB TRUST INTELLIGENCE</span>
        </div>
        <button className="icon-button mobile-close" onClick={onClose} aria-label="Close navigation">
          <Icon name="close" />
        </button>
      </div>

      <div className="workspace-switcher">
        <div className="workspace-avatar">N</div>
        <div className="workspace-copy"><strong>Security workspace</strong><span>Personal plan</span></div>
        <span className="workspace-chevron">⌄</span>
      </div>

      <div className="nav-heading">WORKSPACE</div>
      <nav className="sidebar-nav" aria-label="Main navigation">
        {navigation.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${activeView === item.id ? "active" : ""}`}
            aria-current={activeView === item.id ? "page" : undefined}
            onClick={() => { onNavigate(item.id); onClose?.(); }}
          >
            <Icon name={item.icon} size={18} />
            <span>{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-spacer" />
      <div className="sidebar-bottom">
        <div className="sidebar-note">
          <div className="note-icon"><Icon name="spark" size={16} /></div>
          <div><strong>Stay one step ahead</strong><p>Scan suspicious links before you click.</p></div>
        </div>
        <div className="connection-status">
          <span className={`status-dot ${apiOnline ? "online" : "offline"}`} />
          <span>API {apiOnline ? "connected" : "unavailable"}</span>
          <span className="api-location">:8000</span>
        </div>
        <div className="sidebar-footer"><span>© 2025 NEXVOLT</span><span>v1.0.0</span></div>
      </div>
    </aside>
  );
}
