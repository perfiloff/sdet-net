const API = "/api/v1";

function apiUrl(path) {
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${API}${p}`;
}

function formatJson(obj) {
  return JSON.stringify(obj, null, 2);
}

function showGlobalErr(msg) {
  const el = document.getElementById("global-err");
  if (!msg) {
    el.hidden = true;
    el.textContent = "";
    return;
  }
  el.hidden = false;
  el.textContent = msg;
}

async function apiFetch(path, options = {}) {
  const headers = { ...options.headers };
  const hasBody = options.body != null;
  if (hasBody && typeof options.body === "string" && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const r = await fetch(apiUrl(path), { ...options, headers });
  if (!r.ok) {
    let detail = r.statusText;
    try {
      const j = await r.json();
      if (typeof j.detail === "string") detail = j.detail;
      else if (Array.isArray(j.detail)) detail = j.detail.map((x) => x.msg || JSON.stringify(x)).join("; ");
      else if (j.detail != null) detail = String(j.detail);
      else detail = JSON.stringify(j);
    } catch {
      const t = await r.text();
      if (t) detail = t;
    }
    throw new Error(detail);
  }
  if (r.status === 204) return null;
  const ct = r.headers.get("content-type") || "";
  if (ct.includes("application/json")) return r.json();
  return r.text();
}

function fillTesterPatchForm(cfg) {
  const f = document.getElementById("tester-form-patch");
  if (!cfg || !f) return;
  f.as_number.value = String(cfg.as_number ?? "");
  f.router_id.value = cfg.router_id ?? "";
  f.hold_time.value = String(cfg.hold_time ?? "");
  f.bgp_version.value = String(cfg.bgp_version ?? "");
  f.remote_host.value = cfg.remote_host ?? "";
  f.remote_port.value = String(cfg.remote_port ?? "");
}

async function refreshTesterStatus() {
  showGlobalErr("");
  const data = await apiFetch("/status");
  document.getElementById("tester-status-out").textContent = formatJson(data);
}

async function refreshTesterConfig() {
  showGlobalErr("");
  const data = await apiFetch("/bgp/config");
  document.getElementById("tester-config-out").textContent = formatJson(data);
  fillTesterPatchForm(data);
}

function init() {
  document.getElementById("tester-btn-refresh-status").addEventListener("click", () => {
    refreshTesterStatus().catch((e) => showGlobalErr(e.message));
  });
  document.getElementById("tester-btn-refresh-config").addEventListener("click", () => {
    refreshTesterConfig().catch((e) => showGlobalErr(e.message));
  });
  document.getElementById("tester-btn-ping").addEventListener("click", async () => {
    showGlobalErr("");
    const out = document.getElementById("tester-ping-out");
    out.textContent = "…";
    try {
      out.textContent = await apiFetch("/ping");
    } catch (e) {
      showGlobalErr(e.message);
      out.textContent = "";
    }
  });
  document.getElementById("tester-btn-load-yaml").addEventListener("click", async () => {
    showGlobalErr("");
    const path = document.getElementById("tester-yaml-path").value.trim();
    const reconnect = document.getElementById("tester-yaml-reconnect").checked;
    const q = new URLSearchParams();
    if (path) q.set("path", path);
    if (reconnect) q.set("reconnect", "true");
    const suffix = q.toString() ? `?${q.toString()}` : "";
    try {
      const cfg = await apiFetch(`/bgp/config/load-from-yaml${suffix}`, { method: "POST" });
      document.getElementById("tester-config-out").textContent = formatJson(cfg);
      fillTesterPatchForm(cfg);
      await refreshTesterStatus().catch(() => {});
    } catch (e) {
      showGlobalErr(e.message);
    }
  });
  document.getElementById("tester-form-patch").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showGlobalErr("");
    const f = ev.target;
    const reconnect = f.reconnect.checked;
    const q = reconnect ? "?reconnect=true" : "";
    const body = {
      as_number: parseInt(f.as_number.value, 10),
      router_id: f.router_id.value.trim(),
      hold_time: parseInt(f.hold_time.value, 10),
      bgp_version: parseInt(f.bgp_version.value, 10),
      remote_host: f.remote_host.value.trim(),
      remote_port: parseInt(f.remote_port.value, 10),
    };
    try {
      await apiFetch(`/bgp/config${q}`, { method: "PATCH", body: JSON.stringify(body) });
      await refreshTesterConfig();
      await refreshTesterStatus().catch(() => {});
    } catch (e) {
      showGlobalErr(e.message);
    }
  });
}

init();
refreshTesterConfig().catch(() => {});
refreshTesterStatus().catch(() => {});
