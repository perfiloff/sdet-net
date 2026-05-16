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
  if (!el) {
    if (msg) console.error(msg);
    return;
  }
  if (!msg) {
    el.hidden = true;
    el.textContent = "";
    return;
  }
  el.hidden = false;
  el.textContent = msg;
  el.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function setUploadStatus(msg) {
  const el = document.getElementById("tester-upload-status");
  if (el) el.textContent = msg || "";
}

async function apiFetch(path, options = {}) {
  const isFormData = typeof FormData !== "undefined" && options.body instanceof FormData;
  const headers = { ...(options.headers || {}) };
  const hasBody = options.body != null;
  if (hasBody && typeof options.body === "string" && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const fetchOpts = { ...options };
  if (isFormData) {
    delete fetchOpts.headers;
  } else if (Object.keys(headers).length) {
    fetchOpts.headers = headers;
  }
  const r = await fetch(apiUrl(path), fetchOpts);
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
  const out = document.getElementById("tester-status-out");
  if (out) out.textContent = formatJson(data);
}

async function refreshTesterConfig() {
  showGlobalErr("");
  const data = await apiFetch("/bgp/config");
  const out = document.getElementById("tester-config-out");
  if (out) out.textContent = formatJson(data);
  fillTesterPatchForm(data);
}

async function handleUploadYaml() {
  showGlobalErr("");
  setUploadStatus("");
  const input = document.getElementById("tester-yaml-file");
  const btn = document.getElementById("tester-btn-upload-yaml");
  const file = input?.files?.[0];
  if (!file) {
    showGlobalErr("Choose a YAML file to upload.");
    setUploadStatus("No file selected.");
    return;
  }
  const reconnect = document.getElementById("tester-yaml-reconnect")?.checked ?? false;
  const q = reconnect ? "?reconnect=true" : "";
  const form = new FormData();
  form.append("file", file, file.name);
  const prevLabel = btn?.textContent ?? "Upload & apply";
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Uploading…";
  }
  setUploadStatus(`Uploading ${file.name}…`);
  try {
    const data = await apiFetch(`/bgp/config/upload-yaml${q}`, { method: "POST", body: form });
    if (data?.path) {
      const pathEl = document.getElementById("tester-yaml-target-path");
      if (pathEl) pathEl.textContent = data.path;
    }
    const cfg = data?.config ?? data;
    const out = document.getElementById("tester-config-out");
    if (out) out.textContent = formatJson(cfg);
    fillTesterPatchForm(cfg);
    if (input) input.value = "";
    setUploadStatus(data?.path ? `Saved to ${data.path} and applied.` : "Upload complete.");
    await refreshTesterStatus().catch(() => {});
  } catch (e) {
    const msg = String(e?.message ?? e) || "Upload failed.";
    showGlobalErr(msg);
    setUploadStatus(msg);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = prevLabel;
    }
  }
}

function bindUi() {
  const main = document.querySelector("main");
  if (!main) {
    console.error("tester ui: <main> not found");
    return;
  }

  main.addEventListener("click", (ev) => {
    const id = ev.target?.id;
    if (id === "tester-btn-refresh-status") {
      refreshTesterStatus().catch((e) => showGlobalErr(String(e?.message ?? e)));
    } else if (id === "tester-btn-refresh-config") {
      refreshTesterConfig().catch((e) => showGlobalErr(String(e?.message ?? e)));
    } else if (id === "tester-btn-ping") {
      (async () => {
        showGlobalErr("");
        const out = document.getElementById("tester-ping-out");
        if (out) out.textContent = "…";
        try {
          if (out) out.textContent = await apiFetch("/ping");
        } catch (e) {
          showGlobalErr(String(e?.message ?? e));
          if (out) out.textContent = "";
        }
      })();
    } else if (id === "tester-btn-upload-yaml") {
      ev.preventDefault();
      handleUploadYaml();
    }
  });

  const patchForm = document.getElementById("tester-form-patch");
  patchForm?.addEventListener("submit", async (ev) => {
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
      showGlobalErr(String(e?.message ?? e));
    }
  });
}

async function loadYamlTargetPath() {
  try {
    const data = await apiFetch("/bgp/config/yaml-path");
    const pathEl = document.getElementById("tester-yaml-target-path");
    if (pathEl && data?.path) pathEl.textContent = data.path;
  } catch {
    /* optional hint */
  }
}

try {
  bindUi();
  loadYamlTargetPath().catch(() => {});
  refreshTesterConfig().catch(() => {});
  refreshTesterStatus().catch(() => {});
} catch (e) {
  console.error("tester ui init failed:", e);
  showGlobalErr(`UI failed to start: ${e?.message ?? e}`);
}
