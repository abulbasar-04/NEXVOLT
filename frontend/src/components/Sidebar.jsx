
import React from "react";
import Icon from "./Icon.jsx";

const navigation = [
  { id: "overview", label: "Dashboard", icon: "grid" },
  { id: "trust", label: "Trust dashboard", icon: "target" },
  { id: "scanner", label: "URL scanner", icon: "search" },
  { id: "history", label: "Scan history", icon: "clock" },
  { id: "intelligence", label: "Threat intelligence", icon: "activity" },
  { id: "community-reports", label: "Community reports", icon: "users" },
  { id: "ssl", label: "SSL certificate analysis", icon: "lock" },
  { id: "certificate-monitoring", label: "Certificate monitoring", icon: "shield" },
];

export default function Sidebar({
  activeView,
  onNavigate,
  apiOnline,
  onClose,
}) {
  const [workspaceMenuOpen, setWorkspaceMenuOpen] = React.useState(false);

  return (
    <aside className="sidebar">

      {/* CYBERNOVA BRAND LOGO */}
      <div className="brand">
        <img
          src="/cybernova-logo.png"
          alt="CYBERNOVA - Global Threat Intelligence"
          className="cybernova-logo"
        />

        <button
          className="icon-button mobile-close"
          onClick={onClose}
          aria-label="Close navigation"
        >
          <Icon name="close" />
        </button>
      </div>

      {/* WORKSPACE */}
      <button
        type="button"
        className="workspace-switcher"
        onClick={() => setWorkspaceMenuOpen((open) => !open)}
        title="Open workspace menu"
      >
        <div className="workspace-avatar">
          <img src="/cybernova-logo.png" alt="CYBERNOVA" />
        </div>

        <div className="workspace-copy">
          <strong>Security workspace</strong>
          <span>Free plan</span>
        </div>

        <span className="workspace-chevron">⌄</span>
      </button>

      {workspaceMenuOpen && (
        <div className="workspace-dropdown">
          <div className="workspace-dropdown-title">CYBERNOVA WORKSPACE</div>
          <div className="workspace-plan-card">
            <div className="workspace-plan-heading">
              <strong>FREE PLAN</strong>
              <span>ACTIVE</span>
            </div>
            <div className="workspace-usage-label">
              <span>Demo scan usage</span>
              <span>0 / 20</span>
            </div>
            <div className="workspace-usage-track">
              <div className="workspace-usage-fill" />
            </div>
            <small>Usage display only · Demo interface</small>
          </div>
          <div className="workspace-dropdown-item">
            <span>Security workspace</span>
            <span className="workspace-dropdown-badge">Active</span>
          </div>
          <div className="workspace-dropdown-item">
            <span>Free plan</span>
          </div>
          <button
            type="button"
            className="workspace-dropdown-close"
            onClick={() => setWorkspaceMenuOpen(false)}
          >
            Close menu
          </button>
        </div>
      )}

      <div className="nav-heading">WORKSPACE</div>

      {/* NAVIGATION */}
      <nav className="sidebar-nav" aria-label="Main navigation">
        {navigation.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${
              activeView === item.id ? "active" : ""
            }`}
            aria-current={
              activeView === item.id ? "page" : undefined
            }
            onClick={() => {
              onNavigate(item.id);
              onClose?.();
            }}
          >
            <Icon name={item.icon} size={20} />
            <span>{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-spacer" />

      {/* SIDEBAR BOTTOM */}
      <div className="sidebar-bottom">

        <div className="sidebar-note">
          <div className="note-icon">
            <Icon name="spark" size={16} />
          </div>

          <div>
            <strong>Stay one step ahead</strong>
            <p>Scan suspicious links before you click.</p>
          </div>
        </div>

        <div className="connection-status">
          <span
            className={`status-dot ${
              apiOnline ? "online" : "offline"
            }`}
          />

          <span>
            API {apiOnline ? "connected" : "unavailable"}
          </span>

          <span className="api-location">:8000</span>
        </div>

        <div className="sidebar-footer">
          <span>© CYBERNOVA</span>
          <span>v1.0.0</span>
        </div>

      </div>
    </aside>
  );
}
