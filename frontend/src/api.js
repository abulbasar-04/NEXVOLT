const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000")
  .trim()
  .replace(/\/+$/, "");

let backendIdentityCheck = null;
let backendIdentityCheckedAt = 0;

async function fetchPayload(path, options, timeoutMs) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await fetch(`${API_BASE_URL}${path}`, {
        ...options,
        signal: controller.signal,
        credentials: "include",
        headers: {
          Accept: "application/json",
          ...options.headers,
        },
      });
    } catch (error) {
      if (error.name === "AbortError") {
        throw new Error(`The API request timed out after ${Math.round(timeoutMs / 1000)} seconds.`);
      }
      throw new Error(
        `Could not connect to CYBERNOVA API at ${API_BASE_URL}. Make sure the FastAPI backend is running.`,
      );
    }

    let payload;
    try {
      payload = await response.json();
    } catch {
      if (controller.signal.aborted) {
        throw new Error(`The API request timed out after ${Math.round(timeoutMs / 1000)} seconds.`);
      }
      throw new Error(`The API returned an unreadable response (${response.status}).`);
    }

    if (!response.ok) {
      const detail =
        typeof payload.detail === "string"
          ? payload.detail
          : `Request failed with status ${response.status}`;
      throw new Error(detail);
    }

    return payload;
  } finally {
    window.clearTimeout(timeout);
  }
}

async function verifyBackendIdentity() {
  if (backendIdentityCheck && Date.now() - backendIdentityCheckedAt < 5000) {
    return backendIdentityCheck;
  }

  backendIdentityCheckedAt = Date.now();
  backendIdentityCheck = fetchPayload("/api/health", {}, 15_000)
    .then((health) => {
      if (health.status !== "healthy" || health.service !== "CYBERNOVA Backend") {
        throw new Error(
          "The API at this address is not the expected CYBERNOVA backend. Check VITE_API_BASE_URL and restart the correct server.",
        );
      }
      return health;
    })
    .catch((error) => {
      backendIdentityCheck = null;
      throw error;
    });

  return backendIdentityCheck;
}

async function request(path, { timeoutMs = 15_000, ...options } = {}) {
  if (path !== "/api/health") {
    await verifyBackendIdentity();
  }
  return fetchPayload(path, options, timeoutMs);
}

export function getHealth() {
  return request("/api/health").then((health) => {
    if (health.status !== "healthy" || health.service !== "CYBERNOVA Backend") {
      throw new Error(
        "The API at this address is not the expected CYBERNOVA backend. Check VITE_API_BASE_URL and restart the correct server.",
      );
    }
    return health;
  });
}

export function scanUrl(url) {
  return request("/api/scan", {
    timeoutMs: 120_000,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
}

export function lookupDns(domain) {
  return request(`/api/dns?domain=${encodeURIComponent(domain)}`);
}

export function getCertificateMonitors() {
  return request("/api/certificate-monitoring");
}

export function getCertificateMonitorAlerts() {
  return request("/api/certificate-monitoring/alerts");
}

export function addCertificateMonitor(domain) {
  return request("/api/certificate-monitoring", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
}

export function checkCertificateMonitor(domainId) {
  return request(`/api/certificate-monitoring/${domainId}/check`, {
    method: "POST",
  });
}

export function removeCertificateMonitor(domainId) {
  return request(`/api/certificate-monitoring/${domainId}`, {
    method: "DELETE",
  });
}

export function getCertificateMonitorHistory(domainId) {
  return request(`/api/certificate-monitoring/${domainId}/history`);
}

export function initializeCommunityReportSession() {
  return request("/api/community-reports/session");
}

export function getCommunityReports({ limit = 50, offset = 0 } = {}) {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  return request(`/api/community-reports?${query}`);
}

export function getVerifiedCommunityReports({ limit = 50, offset = 0 } = {}) {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  return request(`/api/community-reports/verified?${query}`);
}

export function submitCommunityReport(report) {
  return request("/api/community-reports", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(report),
  });
}

export function getAdminCommunityReports(token, status = "") {
  const query = status ? `?status=${encodeURIComponent(status)}` : "";
  return request(`/api/community-reports/admin${query}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export function moderateCommunityReport(reportId, token, status, note = "") {
  return request(`/api/community-reports/${reportId}/moderation`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ status, note }),
  });
}

export { API_BASE_URL };
