import { AnsiUp } from "./vendor/ansi_up.js";

const API = "/api/v1";

function apiUrl(path) {
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${API}${p}`;
}

function wsUrl(pathAndQuery) {
  const p = pathAndQuery.startsWith("/") ? pathAndQuery : `/${pathAndQuery}`;
  const u = new URL(apiUrl(p), window.location.origin);
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  return u.toString();
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

function initNav() {
  const buttons = document.querySelectorAll(".nav-btn");
  const panels = document.querySelectorAll(".panel");
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-section");
      buttons.forEach((b) => b.classList.toggle("active", b === btn));
      panels.forEach((p) => p.classList.toggle("active", p.id === `panel-${id}`));
    });
  });
}

function initDashboard() {
  document.getElementById("btn-ping").addEventListener("click", async () => {
    showGlobalErr("");
    const out = document.getElementById("ping-out");
    out.textContent = "…";
    try {
      const text = await apiFetch("/ping");
      out.textContent = text;
    } catch (e) {
      showGlobalErr(e.message);
      out.textContent = "";
    }
  });

  document.getElementById("btn-health").addEventListener("click", async () => {
    showGlobalErr("");
    const box = document.getElementById("health-box");
    try {
      const data = await apiFetch("/dut/health");
      box.hidden = false;
      const sshEl = document.getElementById("health-ssh");
      const vtEl = document.getElementById("health-vtysh");
      sshEl.textContent = data.ssh_reachable ? "yes" : "no";
      sshEl.className = data.ssh_reachable ? "badge-ok" : "badge-bad";
      vtEl.textContent = data.vtysh_ok ? "yes" : "no";
      vtEl.className = data.vtysh_ok ? "badge-ok" : "badge-bad";
      document.getElementById("health-msg").textContent = data.message || "";
    } catch (e) {
      showGlobalErr(e.message);
      box.hidden = true;
    }
  });
}

function renderHostsTable(hosts) {
  const tbody = document.getElementById("hosts-tbody");
  tbody.replaceChildren();
  for (const h of hosts) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${h.index}</td>
      <td>${escapeHtml(h.host)}</td>
      <td>${h.port}</td>
      <td>${escapeHtml(h.username)}</td>
      <td>${h.has_password ? "yes" : "no"}</td>
      <td>${h.has_private_key ? "yes" : "no"}</td>
      <td class="table-actions">
        <button type="button" data-action="edit" data-index="${h.index}">Edit</button>
        <button type="button" data-action="delete" data-index="${h.index}">Delete</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('button[data-action="edit"]').forEach((btn) => {
    btn.addEventListener("click", () => loadHostForEdit(Number(btn.getAttribute("data-index"), 10)));
  });
  tbody.querySelectorAll('button[data-action="delete"]').forEach((btn) => {
    btn.addEventListener("click", () => deleteHost(Number(btn.getAttribute("data-index"), 10)));
  });
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function loadHosts() {
  showGlobalErr("");
  const data = await apiFetch("/config/dut-hosts");
  document.getElementById("hosts-config-path").textContent = `Config file: ${data.config_path}`;
  renderHostsTable(data.hosts);
}

async function loadHostForEdit(index) {
  showGlobalErr("");
  const h = await apiFetch(`/config/dut-hosts/${index}`);
  const form = document.getElementById("form-host-edit");
  const hint = document.getElementById("edit-hint");
  form.hidden = false;
  hint.hidden = true;
  form.index.value = String(h.index);
  form.host.value = h.host;
  form.port.value = String(h.port);
  form.username.value = h.username;
  form.password.value = "";
  form.private_key.value = "";
  form.clear_password.checked = false;
  form.clear_private_key.checked = false;
  form.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function initHosts() {
  document.getElementById("form-host-create").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showGlobalErr("");
    const f = ev.target;
    const portNum = parseInt(f.port.value, 10);
    const body = {
      host: f.host.value.trim(),
      port: Number.isNaN(portNum) ? 22 : portNum,
      username: f.username.value.trim(),
    };
    const pw = f.password.value;
    const pk = f.private_key.value.trim();
    if (pw) body.password = pw;
    if (pk) body.private_key = pk;
    try {
      await apiFetch("/config/dut-hosts", { method: "POST", body: JSON.stringify(body) });
      f.reset();
      f.port.value = "22";
      await loadHosts();
    } catch (e) {
      showGlobalErr(e.message);
    }
  });

  document.getElementById("form-host-edit").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showGlobalErr("");
    const f = ev.target;
    const index = f.index.value;
    const portNum = parseInt(f.port.value, 10);
    if (Number.isNaN(portNum)) {
      showGlobalErr("Invalid port.");
      return;
    }
    const body = {
      host: f.host.value.trim(),
      port: portNum,
      username: f.username.value.trim(),
      clear_password: f.clear_password.checked,
      clear_private_key: f.clear_private_key.checked,
    };
    const pw = f.password.value;
    const pk = f.private_key.value.trim();
    if (pw) body.password = pw;
    if (pk) body.private_key = pk;
    try {
      await apiFetch(`/config/dut-hosts/${index}`, { method: "PUT", body: JSON.stringify(body) });
      f.hidden = true;
      document.getElementById("edit-hint").hidden = false;
      await loadHosts();
    } catch (e) {
      showGlobalErr(e.message);
    }
  });

  document.getElementById("btn-host-edit-cancel").addEventListener("click", () => {
    document.getElementById("form-host-edit").hidden = true;
    document.getElementById("edit-hint").hidden = false;
  });
}

async function deleteHost(index) {
  if (!window.confirm(`Delete DUT host #${index}?`)) return;
  showGlobalErr("");
  try {
    await apiFetch(`/config/dut-hosts/${index}`, { method: "DELETE" });
    await loadHosts();
  } catch (e) {
    showGlobalErr(e.message);
  }
}

function renderSessionsTable(sessions) {
  const tbody = document.getElementById("sessions-tbody");
  tbody.replaceChildren();
  for (const s of sessions) {
    const tr = document.createElement("tr");
    const idTd = document.createElement("td");
    idTd.className = "mono";
    idTd.textContent = s.session_id;
    const epTd = document.createElement("td");
    epTd.textContent = s.endpoint;
    const bootTd = document.createElement("td");
    bootTd.textContent = s.bootstrap ? "yes" : "no";
    const actTd = document.createElement("td");
    actTd.className = "table-actions";
    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.textContent = "Use";
    useBtn.addEventListener("click", () => {
      document.querySelector('#form-session-exec [name="session_id"]').value = s.session_id;
      document.getElementById("shell-session-id").value = s.session_id;
    });
    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.textContent = "Close";
    delBtn.addEventListener("click", () => deleteSession(s.session_id));
    actTd.append(useBtn, delBtn);
    tr.append(idTd, epTd, bootTd, actTd);
    tbody.appendChild(tr);
  }
}

async function refreshSessions() {
  showGlobalErr("");
  const data = await apiFetch("/dut/vtysh/sessions");
  renderSessionsTable(data.sessions);
}

async function deleteSession(sessionId) {
  if (!window.confirm(`Close session ${sessionId}?`)) return;
  showGlobalErr("");
  try {
    await apiFetch(`/dut/vtysh/sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE" });
    await refreshSessions();
  } catch (e) {
    showGlobalErr(e.message);
  }
}

function buildSessionCreateBody(form) {
  const host = form.host.value.trim();
  const username = form.username.value.trim();
  const portStr = form.port.value.trim();
  const password = form.password.value;
  const private_key = form.private_key.value.trim();
  const any =
    host || username || portStr || password || private_key;
  if (!any) return {};
  if (!host || !username) {
    throw new Error("SSH override requires host and username.");
  }
  const port = portStr ? parseInt(portStr, 10) : 22;
  if (Number.isNaN(port) || port < 1 || port > 65535) {
    throw new Error("Invalid port.");
  }
  const ssh = { host, port, username };
  if (password) ssh.password = password;
  if (private_key) ssh.private_key = private_key;
  return { ssh };
}

function initSessions() {
  document.getElementById("btn-sessions-refresh").addEventListener("click", () => {
    refreshSessions().catch((e) => showGlobalErr(e.message));
  });

  document.getElementById("form-session-create").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showGlobalErr("");
    try {
      const body = buildSessionCreateBody(ev.target);
      const created = await apiFetch("/dut/vtysh/sessions", {
        method: "POST",
        body: JSON.stringify(body),
      });
      ev.target.reset();
      document.getElementById("session-exec-out").textContent = `Created session: ${created.session_id}`;
      await refreshSessions();
    } catch (e) {
      showGlobalErr(e.message);
    }
  });

  const outEl = document.getElementById("session-exec-out");

  document.getElementById("btn-show").addEventListener("click", async () => {
    showGlobalErr("");
    const f = document.getElementById("form-session-exec");
    const sid = f.session_id.value.trim();
    const cmd = f.show_command.value.trim();
    if (!sid || !cmd) {
      showGlobalErr("Session ID and show command are required.");
      return;
    }
    try {
      const res = await apiFetch(`/dut/vtysh/sessions/${encodeURIComponent(sid)}/show`, {
        method: "POST",
        body: JSON.stringify({ command: cmd }),
      });
      outEl.textContent = res.output ?? "";
    } catch (e) {
      showGlobalErr(e.message);
    }
  });

  document.getElementById("btn-configure").addEventListener("click", async () => {
    showGlobalErr("");
    const f = document.getElementById("form-session-exec");
    const sid = f.session_id.value.trim();
    const raw = f.configure_lines.value;
    const commands = raw
      .split(/\r?\n/)
      .map((line) => line.trimEnd())
      .filter((line) => line.length > 0);
    if (!sid || commands.length === 0) {
      showGlobalErr("Session ID and at least one configure line are required.");
      return;
    }
    try {
      const res = await apiFetch(`/dut/vtysh/sessions/${encodeURIComponent(sid)}/configure`, {
        method: "POST",
        body: JSON.stringify({ commands }),
      });
      outEl.textContent = res.output ?? "";
    } catch (e) {
      showGlobalErr(e.message);
    }
  });
}

let logsWs = null;

function setLogsLiveUi(active) {
  const btn = document.getElementById("logs-live-toggle");
  const status = document.getElementById("logs-live-status");
  if (active) {
    btn.textContent = "Stop live stream";
    status.textContent = "Streaming…";
  } else {
    btn.textContent = "Start live stream";
    status.textContent = "";
  }
}

function initLogs() {
  const out = document.getElementById("logs-out");

  document.getElementById("logs-refresh").addEventListener("click", async () => {
    showGlobalErr("");
    const source = document.getElementById("logs-source").value;
    const tail = document.getElementById("logs-tail").value;
    try {
      const text = await apiFetch(`/logs/${encodeURIComponent(source)}?tail=${encodeURIComponent(tail)}`);
      out.textContent = text;
      out.scrollTop = out.scrollHeight;
    } catch (e) {
      showGlobalErr(e.message);
    }
  });

  document.getElementById("logs-live-toggle").addEventListener("click", () => {
    showGlobalErr("");
    if (logsWs) {
      logsWs.close();
      logsWs = null;
      setLogsLiveUi(false);
      return;
    }
    const source = document.getElementById("logs-source").value;
    const u = wsUrl(`/stream/logs?sources=${encodeURIComponent(source)}`);
    const ws = new WebSocket(u);
    logsWs = ws;
    setLogsLiveUi(true);
    out.textContent = "";
    ws.onmessage = (ev) => {
      out.textContent += ev.data;
      out.scrollTop = out.scrollHeight;
    };
    ws.onerror = () => {
      showGlobalErr("Log WebSocket error.");
    };
    ws.onclose = () => {
      if (logsWs === ws) {
        logsWs = null;
        setLogsLiveUi(false);
      }
    };
  });
}

let shellWs = null;

function setShellConnected(connected) {
  document.getElementById("shell-connect").disabled = connected;
  document.getElementById("shell-disconnect").disabled = !connected;
  document.getElementById("shell-in").disabled = !connected;
  document.getElementById("shell-send").disabled = !connected;
}

function initShell() {
  const out = document.getElementById("shell-out");
  const inp = document.getElementById("shell-in");

  document.getElementById("shell-connect").addEventListener("click", () => {
    showGlobalErr("");
    const sid = document.getElementById("shell-session-id").value.trim();
    if (!sid) {
      showGlobalErr("Session ID is required.");
      return;
    }
    if (shellWs) shellWs.close();
    const shellAnsi = new AnsiUp();
    const u = wsUrl(`/dut/vtysh/sessions/${encodeURIComponent(sid)}/shell`);
    const ws = new WebSocket(u);
    shellWs = ws;
    out.innerHTML = "";
    setShellConnected(false);
    ws.binaryType = "arraybuffer";
    ws.onopen = () => {
      if (shellWs === ws) setShellConnected(true);
    };
    ws.onmessage = (ev) => {
      let chunk;
      if (typeof ev.data === "string") chunk = ev.data;
      else {
        const dec = new TextDecoder("utf-8", { fatal: false });
        chunk = dec.decode(ev.data);
      }
      out.innerHTML += shellAnsi.ansi_to_html(chunk);
      out.scrollTop = out.scrollHeight;
    };
    ws.onerror = () => showGlobalErr("Shell WebSocket error.");
    ws.onclose = () => {
      if (shellWs === ws) {
        shellWs = null;
        setShellConnected(false);
      }
    };
  });

  document.getElementById("shell-disconnect").addEventListener("click", () => {
    if (shellWs) {
      shellWs.close();
      shellWs = null;
    }
    setShellConnected(false);
  });

  function sendShell() {
    if (!shellWs || shellWs.readyState !== WebSocket.OPEN) return;
    let text = inp.value;
    if (!text) return;
    if (!text.endsWith("\n")) text += "\n";
    shellWs.send(text);
    inp.value = "";
  }

  document.getElementById("shell-send").addEventListener("click", sendShell);
  inp.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter" || ev.shiftKey) return;
    ev.preventDefault();
    sendShell();
  });
}

function onTabDataLoad() {
  document.querySelector('[data-section="hosts"]').addEventListener("click", () => {
    loadHosts().catch((e) => showGlobalErr(e.message));
  });
  document.querySelector('[data-section="sessions"]').addEventListener("click", () => {
    refreshSessions().catch((e) => showGlobalErr(e.message));
  });
}

initNav();
initDashboard();
initHosts();
initSessions();
initLogs();
initShell();
onTabDataLoad();
