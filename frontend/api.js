// Data access for the dashboard. Owner: E.
//
// Everything comes from the Blindspot server, and the server only knows what
// agents on real computers have reported. There is no built-in demo data.

const Api = (() => {
  async function getJson(url) {
    const res = await fetch(url, { headers: { Accept: "application/json" }, cache: "no-store" });
    if (!res.ok) throw new Error(`${url} -> ${res.status}`);
    return res.json();
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      let detail = `${url} -> ${res.status}`;
      try { detail = (await res.json()).detail || detail; } catch { /* not JSON */ }
      throw new Error(detail);
    }
    return res.json();
  }

  async function getText(url) {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`${url} -> ${res.status}`);
    return res.text();
  }

  return {
    init: () => getJson("/api/v1/health"),
    serverInfo: () => getJson("/api/v1/server-info"),
    summary: () => getJson("/api/v1/fleet/summary"),
    extensions: () => getJson("/api/v1/extensions"),
    extension: (id) => getJson(`/api/v1/extensions/${encodeURIComponent(id)}`).catch(() => null),
    machines: () => getJson("/api/v1/machines"),
    machine: (id) => getJson(`/api/v1/machines/${encodeURIComponent(id)}`).catch(() => null),
    software: () => getJson("/api/v1/software"),
    exposure: () => getJson("/api/v1/exposure"),
    guard: () => getJson("/api/v1/guard"),
    approve: (id, version) =>
      post(`/api/v1/guard/extensions/${encodeURIComponent(id)}/approve` + (version ? `?version=${encodeURIComponent(version)}` : "")),
    syncFeed: () => post("/api/v1/guard/advisories/sync"),
    resetFeed: () => post("/api/v1/guard/advisories/reset"),
    clearAll: () => post("/api/v1/admin/clear"),
    feeds: () => getJson("/api/v1/software/feeds"),
    refreshFeeds: () => post("/api/v1/software/feeds/refresh"),
    approveSoftware: (name, version, publisher) => post("/api/v1/software/approve", { name, version, publisher }),
    unapproveSoftware: (name) => post("/api/v1/software/unapprove", { name }),
    setNvdKey: (key) => post("/api/v1/settings/nvd-key", { key }),
    alerts: () => getJson("/api/v1/alerts"),
    findChats: (token) => post("/api/v1/alerts/telegram/find-chats", { token }),
    saveTelegram: (body) => post("/api/v1/alerts/telegram", body),
    disableTelegram: () => post("/api/v1/alerts/telegram/disable"),
    testAlert: () => post("/api/v1/alerts/test"),
    policy: (query = "") => getJson("/api/v1/policy.json" + query),
    policyReg: () => getText("/api/v1/policy.reg"),
    softwarePolicy: () => getJson("/api/v1/software-policy.json"),
    applocker: () => getText("/api/v1/software-policy.xml"),
    agentZipUrl: (server) => `/api/v1/agent.zip?server=${encodeURIComponent(server)}`,
    reportUrl: () => "/api/v1/report.html",
  };
})();
