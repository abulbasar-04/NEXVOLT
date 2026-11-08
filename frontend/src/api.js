const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000")
  .trim()
  .replace(/\/+$/, "");

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        Accept: "application/json",
        ...options.headers,
      },
    });
  } catch {
    throw new Error(
      `Could not connect to NEXVOLT API at ${API_BASE_URL}. Make sure the FastAPI backend is running.`,
    );
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
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
}

export function getHealth() {
  return request("/api/health");
}

export function scanUrl(url) {
  return request("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
}

export function lookupDns(domain) {
  return request(`/api/dns?domain=${encodeURIComponent(domain)}`);
}

export { API_BASE_URL };
