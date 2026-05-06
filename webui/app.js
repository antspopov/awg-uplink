function $(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element: #${id}`);
  return el;
}

function basePath() {
  return (window.__AWG_BASE_PATH__ || "/").replace(/\/?$/, "/");
}

function fmtBytesPerSec(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v.toFixed(0)} B/s`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB/s`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
}

function fmtBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v.toFixed(0)} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function fmtUptime(sec) {
  const s = Math.max(0, Number(sec) || 0);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}д ${h}ч ${m}м`;
  if (h > 0) return `${h}ч ${m}м`;
  return `${m}м`;
}

function setOptions(selectEl, options, preferred) {
  selectEl.innerHTML = "";
  for (const opt of options) {
    const o = document.createElement("option");
    o.value = opt.value;
    o.textContent = opt.label;
    selectEl.appendChild(o);
  }
  if (preferred) {
    const found = options.find((o) => o.value === preferred);
    if (found) selectEl.value = preferred;
  }
}

function setTunnelStatus(kind, text) {
  const root = $("tunnelStatus");
  const dot = root.querySelector(".dot");
  const statusText = root.querySelector(".status-text");
  dot.classList.remove("dot--unknown", "dot--ok", "dot--warn", "dot--bad");
  dot.classList.add(kind);
  statusText.textContent = text;
}

function setStatusById(rootId, kind, text) {
  const root = document.getElementById(rootId);
  if (!root) return;
  const dot = root.querySelector(".dot");
  const statusText = root.querySelector(".status-text");
  if (!dot || !statusText) return;
  dot.classList.remove("dot--unknown", "dot--ok", "dot--warn", "dot--bad");
  dot.classList.add(kind);
  statusText.textContent = text;
}

function guessGateway(ip) {
  const m = String(ip || "").match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return "";
  return `${m[1]}.${m[2]}.${m[3]}.1`;
}

function ipv4MetaForDevice(ifaces, devName, ip) {
  const dev = ifaces.find((d) => d.name === devName);
  if (!dev) return null;
  const infos = Array.isArray(dev.ipv4_info) ? dev.ipv4_info : [];
  return infos.find((x) => x && x.ip === ip) || null;
}

function gatewayFitsSubnet(gw, cidr) {
  const g = String(gw || "").trim();
  const c = String(cidr || "").trim();
  if (!g || !c || !c.includes("/")) return false;
  const [netIp, pfxRaw] = c.split("/");
  const pfx = Number(pfxRaw);
  if (!Number.isInteger(pfx) || pfx < 0 || pfx > 32) return false;
  const toInt = (ip) => {
    const p = String(ip).split(".").map((n) => Number(n));
    if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    return ((p[0] << 24) >>> 0) + ((p[1] << 16) >>> 0) + ((p[2] << 8) >>> 0) + (p[3] >>> 0);
  };
  const gwInt = toInt(g);
  const ipInt = toInt(netIp);
  if (gwInt == null || ipInt == null) return false;
  const mask = pfx === 0 ? 0 : ((0xffffffff << (32 - pfx)) >>> 0);
  return (gwInt & mask) === (ipInt & mask);
}

function autoFillGateway(gwInput, selectedIp, selectedMeta = null) {
  const auto = (selectedMeta && selectedMeta.suggested_gw) || guessGateway(selectedIp);
  const current = gwInput.value.trim();
  const prevAuto = gwInput.dataset.autoValue || "";
  const untouched = current === "" || current === prevAuto;
  const invalidForSubnet = selectedMeta && selectedMeta.cidr ? !gatewayFitsSubnet(current, selectedMeta.cidr) : false;
  if (untouched || invalidForSubnet) {
    gwInput.value = auto;
  }
  gwInput.dataset.autoValue = auto;
}

function ipv4OptionsForDevice(ifaces, devName) {
  const dev = ifaces.find((d) => d.name === devName);
  const infos = dev && Array.isArray(dev.ipv4_info) ? dev.ipv4_info : [];
  if (infos.length > 0) {
    return infos.map((it) => ({
      value: it.ip,
      label: it.cidr || it.ip,
    }));
  }
  const ips = dev ? dev.ipv4 : [];
  if (ips.length === 0) return [{ value: "", label: "(нет IPv4)" }];
  return ips.map((ip) => ({ value: ip, label: ip }));
}

function initSelectPairs(devId, ipId, gwId, ifaces, preferredDev) {
  const devSel = $(devId);
  const ipSel = $(ipId);
  const gwInput = $(gwId);

  const devOpts = ifaces.map((d) => ({ value: d.name, label: d.name }));
  setOptions(devSel, devOpts, preferredDev || (devOpts[0] ? devOpts[0].value : ""));

  setOptions(ipSel, ipv4OptionsForDevice(ifaces, devSel.value));
  autoFillGateway(gwInput, ipSel.value, ipv4MetaForDevice(ifaces, devSel.value, ipSel.value));

  devSel.addEventListener("change", () => {
    setOptions(ipSel, ipv4OptionsForDevice(ifaces, devSel.value));
    autoFillGateway(gwInput, ipSel.value, ipv4MetaForDevice(ifaces, devSel.value, ipSel.value));
  });
  ipSel.addEventListener("change", () => {
    autoFillGateway(gwInput, ipSel.value, ipv4MetaForDevice(ifaces, devSel.value, ipSel.value));
  });
}

function openModal() {
  const ov = $("importModalOverlay");
  ov.classList.remove("hidden");
  ov.setAttribute("aria-hidden", "false");
  $("confText").focus();
}

function closeModal() {
  const ov = $("importModalOverlay");
  ov.classList.add("hidden");
  ov.setAttribute("aria-hidden", "true");
}

function initImportModal(state) {
  const help = $("confHelp");
  const applyBtn = $("importApplyBtn");
  const fileInput = $("confFileInput");
  const chooseFileBtn = $("chooseFileBtn");
  const openTextBtn = $("openImportModalBtn");
  const restartBtn = $("restartTunnelBtn");

  function render() {
    const hasText = Boolean((state.confText || "").trim());
    const f = fileInput.files && fileInput.files[0];
    const hasFile = Boolean(f);
    const mode = state.importMode || (hasText ? "text" : hasFile ? "file" : "");

    if (mode === "text" && hasText) {
      help.textContent = `Готово к импорту: текст (${(state.confText || "").trim().length} символов).`;
      applyBtn.disabled = false;
      return;
    }
    if (mode === "file" && hasFile) {
      help.textContent = `Готово к импорту: файл (${f.name}).`;
      applyBtn.disabled = false;
      return;
    }
    help.textContent = "Конфиг не задан.";
    applyBtn.disabled = true;
  }

  openTextBtn.addEventListener("click", () => {
    $("confText").value = state.confText || "";
    openModal();
  });
  $("importModalCloseBtn").addEventListener("click", closeModal);
  $("importModalCancelBtn").addEventListener("click", closeModal);
  $("importModalOverlay").addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "importModalOverlay") closeModal();
  });
  window.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeModal();
  });

  $("importModalSaveBtn").addEventListener("click", () => {
    state.confText = $("confText").value;
    state.importMode = "text";
    closeModal();
    render();
  });

  chooseFileBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    state.importMode = "file";
    state.confText = "";
    render();
  });

  $("importApplyBtn").addEventListener("click", async () => {
    try {
      let cfgText = "";
      const f = fileInput.files && fileInput.files[0];
      if (state.importMode === "file" && f) {
        cfgText = await f.text();
      } else {
        cfgText = String(state.confText || "");
      }
      if (!cfgText.trim()) {
        toast("Конфиг не задан.", "error", 2200);
        return;
      }
      setTunnelStatus("dot--warn", "awg-uplink: импорт конфигурации");
      await postJson("/api/tunnel/validate", { config_text: cfgText });
      await postJson("/api/tunnel/import", { config_text: cfgText });
      toast("Конфиг awg-uplink импортирован.", "ok");
      await refreshTunnelStatus(state);
    } catch (e) {
      setTunnelStatus("dot--bad", "awg-uplink: ошибка импорта");
      toast(`Ошибка импорта: ${e?.message || "unknown"}`, "error", 3000);
    }
  });

  restartBtn.addEventListener("click", async () => {
    try {
      setTunnelStatus("dot--warn", "awg-uplink: перезапуск");
      await postJson("/api/tunnel/restart", {});
      toast("awg-uplink перезапущен.", "ok");
      await refreshTunnelStatus(state);
    } catch (e) {
      setTunnelStatus("dot--bad", "awg-uplink: ошибка перезапуска");
      toast(`Ошибка перезапуска: ${e?.message || "unknown"}`, "error", 2800);
    }
  });

  render();
}

async function fetchJson(path) {
  const res = await fetch(`${basePath()}${path.replace(/^\//, "")}`, { credentials: "include" });
  if (res.status === 401) {
    const next = encodeURIComponent(window.location.pathname);
    window.location.href = `${basePath()}login.html?next=${next}`;
    return null;
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

function setRoutingAvailability(enabled) {
  const root = $("routingModes");
  for (const btn of root.querySelectorAll(".routing-mode-btn")) {
    btn.disabled = !enabled;
  }
  if (!enabled) {
    setStatusById("routingModeStatus", "dot--ok", "маршрутизируем в egress (по умолчанию)");
  }
}

function setRouteModeStatus(mode, applied = true) {
  if (!applied) {
    setStatusById("routingModeStatus", "dot--warn", `не применено: ${routeModeLabel(mode)}`);
    return;
  }
  if (mode === "tunnel") {
    setStatusById("routingModeStatus", "dot--ok", "применено: весь трафик в туннель");
  } else if (mode === "egress") {
    setStatusById("routingModeStatus", "dot--ok", "применено: маршрутизируем в egress");
  } else {
    setStatusById("routingModeStatus", "dot--warn", `не применено: ${routeModeLabel(mode)}`);
  }
}

async function refreshTunnelStatus(state = null) {
  try {
    const st = await fetchJson("/api/status/awg-uplink");
    if (!st) return;
    const up = Boolean(st.exists && st.state === "UP");
    if (state) state.tunnelUp = up;
    setRoutingAvailability(up);
    if (!st.exists) return setTunnelStatus("dot--bad", st.configured ? "awg-uplink: DOWN" : "awg-uplink: не настроен");
    const op = st.operstate && st.operstate !== "UNKNOWN" ? st.operstate : "";
    if (st.state === "UP") return setTunnelStatus("dot--ok", `awg-uplink: UP${op ? ` (${op})` : ""}`);
    const base = st.state || "UNKNOWN";
    return setTunnelStatus("dot--warn", `awg-uplink: ${base}${op ? ` (${op})` : ""}`);
  } catch {
    if (state) state.tunnelUp = false;
    setRoutingAvailability(false);
    setTunnelStatus("dot--unknown", "awg-uplink: ошибка статуса");
  }
}

async function refreshSystemMetrics(state) {
  try {
    const m = await fetchJson("/api/metrics/system");
    if (!m) return;

    // CPU %
    let cpuPct = 0;
    if (state.prevCpu && m.cpu_total > state.prevCpu.total) {
      const dt = m.cpu_total - state.prevCpu.total;
      const di = m.cpu_idle - state.prevCpu.idle;
      cpuPct = Math.max(0, Math.min(100, ((dt - di) / dt) * 100));
    }
    state.prevCpu = { total: m.cpu_total, idle: m.cpu_idle };

    // Memory %
    const memUsedKb = Math.max(0, (m.mem_total_kb || 0) - (m.mem_avail_kb || 0));
    const memPct = m.mem_total_kb > 0 ? (memUsedKb / m.mem_total_kb) * 100 : 0;

    // Net rate
    let rxRate = 0;
    let txRate = 0;
    if (state.prevNet && m.ts > state.prevNet.ts) {
      const dt = m.ts - state.prevNet.ts;
      rxRate = Math.max(0, (m.net_rx_bytes - state.prevNet.rx) / dt);
      txRate = Math.max(0, (m.net_tx_bytes - state.prevNet.tx) / dt);
    }
    state.prevNet = { ts: m.ts, rx: m.net_rx_bytes, tx: m.net_tx_bytes };

    $("mCpu").textContent = `${cpuPct.toFixed(1)}%`;
    $("mCpuBar").style.width = `${cpuPct.toFixed(1)}%`;
    $("mMem").textContent = `${memPct.toFixed(1)}%`;
    $("mMemBar").style.width = `${Math.max(0, Math.min(100, memPct)).toFixed(1)}%`;
    $("mMemDetails").textContent = `${fmtBytes(memUsedKb * 1024)} / ${fmtBytes((m.mem_total_kb || 0) * 1024)}`;
    $("mNet").textContent = `${fmtBytesPerSec(rxRate)} / ${fmtBytesPerSec(txRate)}`;
    $("mNetTotals").textContent = `Σ ${fmtBytes(m.net_rx_bytes)} / ${fmtBytes(m.net_tx_bytes)}`;
    $("mLoad").textContent = `${(m.load1 || 0).toFixed(2)} ${(m.load5 || 0).toFixed(2)} ${(m.load15 || 0).toFixed(2)}`;
    $("mCpuCount").textContent = `CPU: ${m.cpu_count || 0}`;
    $("mUptime").textContent = fmtUptime(m.uptime_sec || 0);
    const d = new Date();
    $("mUpdatedAt").textContent = `обновление: ${d.toLocaleTimeString()}`;
  } catch {
    // keep last values on temporary errors
  }
}

async function postJson(path, body) {
  const res = await fetch(`${basePath()}${path.replace(/^\//, "")}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  return res.json().catch(() => ({}));
}

async function copyText(text) {
  const t = String(text || "");
  if (!t) return false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(t);
      return true;
    }
  } catch {
    // fallback below
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = t;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

function shortSecret(s) {
  if (!s) return "";
  return s.length <= 12 ? s : `${s.slice(0, 6)}...${s.slice(-6)}`;
}

function tgToTme(link) {
  if (!link) return "";
  if (link.startsWith("tg://")) return `https://t.me/${link.slice("tg://".length)}`;
  return link;
}

function randomHex(nBytes) {
  const a = new Uint8Array(nBytes);
  crypto.getRandomValues(a);
  return Array.from(a)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function isSecretValid(secret) {
  return /^[0-9a-fA-F]{32}$/.test(secret);
}

function setUserFormStatus(text, kind = "") {
  const el = $("mtpUserFormStatus");
  el.textContent = text || "";
  el.classList.remove("error", "ok");
  if (kind) el.classList.add(kind);
}

function toast(message, kind = "ok", ttlMs = 1800) {
  let wrap = document.getElementById("toastWrap");
  if (!wrap) {
    wrap = document.createElement("div");
    wrap.id = "toastWrap";
    wrap.className = "toast-wrap";
    document.body.appendChild(wrap);
  }
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = message;
  wrap.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 220);
  }, ttlMs);
}

function renderMtprotoUsers(users) {
  const body = $("mtpUsersBody");
  body.innerHTML = "";
  for (const u of users) {
    const row = document.createElement("div");
    row.className = "mtp-user-item";
    const link = u.link || "";
    const enabled = Boolean(u.enabled);
    const sessions = Number(u.sessions || 0);
    const linkTme = u.link_tme || tgToTme(link);
    row.innerHTML = `
      <button class="switch ${enabled ? "is-on" : ""}" data-toggle-user="${u.username || ""}" data-enabled="${enabled ? "1" : "0"}" type="button" title="${enabled ? "Выключить" : "Включить"}"></button>
      <div class="mtp-user-main">
        <div class="mtp-user-name">${u.username || ""}</div>
        <div class="mtp-user-meta">secret: ${shortSecret(u.secret || "")}</div>
      </div>
      <div class="mtp-user-sessions">${sessions}</div>
      <div class="mtp-user-link" title="${link}">${link || "tg://—"}</div>
      <div class="mtp-user-actions">
        <button class="mini-btn user-action" data-copy-link="${u.username || ""}" type="button" ${link ? "" : "disabled"}>Copy tg://</button>
        <button class="mini-btn user-action" data-copy-tme="${u.username || ""}" type="button" ${link ? "" : "disabled"}>Copy t.me</button>
        <button class="mini-btn user-action" data-edit-user="${u.username || ""}" type="button">✎</button>
        <button class="mini-btn mini-btn--danger user-action" data-del-user="${u.username || ""}" type="button" title="Удалить">✕</button>
      </div>
    `;
    row.dataset.link = link;
    row.dataset.linkTme = linkTme;
    row.dataset.secret = u.secret || "";
    row.dataset.sessions = String(sessions);
    body.appendChild(row);
  }
}

async function refreshMtprotoState(state) {
  try {
    const s = await fetchJson("/api/mtproto/state");
    if (!s) return;

    state.mtproto = s;
    $("mtpConfigPathLabel").textContent = `Путь: ${s.config_path || "--"}`;
    $("mtpConfigText").value = s.config_text || "";

    const users = s.users || [];
    renderMtprotoUsers(users);
    const usersCount = Number(s.users_total ?? users.length);
    const sessionsOpen = Number(s.sessions_total ?? users.reduce((acc, u) => acc + Number(u.sessions || 0), 0));
    const sessionsCap = Number(s.sessions_cap ?? usersCount * 9);
    const unassigned = Number(s.unassigned ?? Math.max(0, sessionsCap - sessionsOpen));
    $("mtpUsersMeta").textContent = `${usersCount} users · sessions ${sessionsOpen}/${sessionsCap} · unassigned ${unassigned}`;
    setStatusById("mtprotoUsersStatus", "dot--ok", `загружено`);
    setStatusById("mtpConfigStatus", s.config_exists ? "dot--ok" : "dot--warn", s.config_exists ? "загружен" : "не найден");
    const svc = s.service || {};
    const svcName = svc.name || "mtproto-proxy";
    const svcState = svc.state || "unknown";
    const svcOk = Boolean(svc.ok);
    setStatusById(
      "mtprotoServiceStatus",
      svcOk ? "dot--ok" : "dot--bad",
      `health: ${svcName} ${svcState}`
    );

    const mh = s.masking_health || {};
    const ok = Boolean(mh.ok);
    const enabled = mh.enabled !== false;
    const mode = mh.mode || "local";
    if (!enabled) {
      setStatusById("mtpMaskStatus", "dot--warn", "Disabled");
    } else if (mode === "remote") {
      setStatusById("mtpMaskStatus", "dot--ok", "Remote mode");
    } else {
      setStatusById("mtpMaskStatus", ok ? "dot--ok" : "dot--warn", ok ? "Healthy" : "Degraded");
    }
    $("mtpMaskModeValue").textContent = mode;
    const endpoint = mh.endpoint || `127.0.0.1:${String(s.censorship?.mask_port ?? "--")}`;
    const endpointState = mh.endpoint_status || (mh.endpoint_ok ? "OK" : "DOWN");
    $("mtpMaskEndpointValue").textContent = `${endpoint} (${endpointState})`;
    const nginx = mh.nginx || {};
    $("mtpNginxValue").textContent = `${nginx.active || "unknown"} / ${nginx.enabled || "unknown"}`;
    const timer = mh.health_timer || {};
    $("mtpHealthTimerValue").textContent = `${timer.active || "unknown"} / ${timer.enabled || "unknown"}`;
  } catch {
    setStatusById("mtprotoUsersStatus", "dot--bad", "ошибка загрузки");
    setStatusById("mtprotoServiceStatus", "dot--bad", "health: ошибка");
    setStatusById("mtpMaskStatus", "dot--bad", "ошибка загрузки");
    setStatusById("mtpConfigStatus", "dot--bad", "ошибка загрузки");
  }
}

function initMtprotoPanel(state) {
  $("mtpOpenAddUserBtn").addEventListener("click", () => {
    state.editingUser = "";
    $("mtpUserModalTitle").textContent = "Add User";
    $("mtpUserName").disabled = false;
    $("mtpUserName").value = "";
    $("mtpUserSecret").value = "";
    setUserFormStatus("");
    $("mtpUserModalOverlay").classList.remove("hidden");
  });
  $("mtpOpenConfigBtn").addEventListener("click", () => {
    $("mtpConfigModalOverlay").classList.remove("hidden");
  });

  $("mtpUserModalCloseBtn").addEventListener("click", () => {
    setUserFormStatus("");
    $("mtpUserModalOverlay").classList.add("hidden");
  });
  $("mtpUserModalCancelBtn").addEventListener("click", () => {
    setUserFormStatus("");
    $("mtpUserModalOverlay").classList.add("hidden");
  });
  $("mtpConfigModalCloseBtn").addEventListener("click", () => $("mtpConfigModalOverlay").classList.add("hidden"));
  $("mtpConfigModalCancelBtn").addEventListener("click", () => $("mtpConfigModalOverlay").classList.add("hidden"));

  $("mtpUserSaveBtn").addEventListener("click", async () => {
    const username = $("mtpUserName").value.trim();
    let secret = $("mtpUserSecret").value.trim();
    if (!username) {
      setUserFormStatus("Введите имя пользователя.", "error");
      return;
    }
    if (!secret) {
      secret = randomHex(16);
      $("mtpUserSecret").value = secret;
      setUserFormStatus("Секрет сгенерирован автоматически.", "ok");
    }
    if (!isSecretValid(secret)) {
      setUserFormStatus("Неверный secret: нужен формат 32 hex-символа.", "error");
      $("mtpUserSecret").focus();
      return;
    }
    try {
      await postJson("/api/mtproto/users/upsert", { username, secret });
      setUserFormStatus("Сохранено.", "ok");
      await refreshMtprotoState(state); // immediate refresh
      toast("Пользователь сохранен.", "ok");
      $("mtpUserName").value = "";
      $("mtpUserSecret").value = "";
      $("mtpUserModalOverlay").classList.add("hidden");
    } catch (e) {
      setUserFormStatus(`Ошибка сохранения: ${e && e.message ? e.message : e}`, "error");
      toast("Ошибка сохранения пользователя.", "error", 2200);
    }
  });

  $("mtpUsersBody").addEventListener("click", async (ev) => {
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    const uname = t.getAttribute("data-del-user");
    const toggleUser = t.getAttribute("data-toggle-user");
    const copyUser = t.getAttribute("data-copy-link");
    const copyTmeUser = t.getAttribute("data-copy-tme");
    const editUser = t.getAttribute("data-edit-user");
    if (uname) {
      try {
        await postJson("/api/mtproto/users/delete", { username: uname });
        await refreshMtprotoState(state); // immediate refresh
        toast("Пользователь удален.", "ok");
      } catch {
        setStatusById("mtprotoUsersStatus", "dot--bad", "ошибка удаления");
        toast("Ошибка удаления пользователя.", "error", 2200);
      }
      return;
    }
    if (toggleUser) {
      const enabledNow = t.getAttribute("data-enabled") === "1";
      try {
        await postJson("/api/mtproto/users/toggle", { username: toggleUser, enabled: !enabledNow });
        await refreshMtprotoState(state); // immediate refresh
        toast(enabledNow ? "Пользователь выключен." : "Пользователь включен.", "ok");
      } catch {
        setStatusById("mtprotoUsersStatus", "dot--bad", "ошибка переключения");
        toast("Ошибка переключения пользователя.", "error", 2200);
      }
      return;
    }
    if (copyUser || copyTmeUser) {
      const card = t.closest(".mtp-user-item");
      const link = card ? card.dataset.link || "" : "";
      const linkTme = card ? card.dataset.linkTme || "" : "";
      if (!link) return;
      if (copyUser) {
        const ok = await copyText(link);
        toast(ok ? "Ссылка tg:// скопирована." : "Не удалось скопировать ссылку.", ok ? "ok" : "error");
      } else if (copyTmeUser) {
        const ok = await copyText(linkTme || tgToTme(link));
        toast(ok ? "Ссылка t.me скопирована." : "Не удалось скопировать ссылку.", ok ? "ok" : "error");
      }
      return;
    }
    if (editUser) {
      const card = t.closest(".mtp-user-item");
      $("mtpUserModalTitle").textContent = "Edit User";
      $("mtpUserName").value = editUser;
      $("mtpUserName").disabled = true;
      $("mtpUserSecret").value = card ? card.dataset.secret || "" : "";
      setUserFormStatus("");
      $("mtpUserModalOverlay").classList.remove("hidden");
      return;
    }
  });

  $("mtpConfigSaveBtn").addEventListener("click", async () => {
    try {
      await postJson("/api/mtproto/config/save", { config_text: $("mtpConfigText").value });
      setStatusById("mtpConfigStatus", "dot--ok", "сохранено");
      $("mtpConfigModalOverlay").classList.add("hidden");
      await refreshMtprotoState(state);
      toast("config.toml сохранен.", "ok");
    } catch {
      setStatusById("mtpConfigStatus", "dot--bad", "ошибка сохранения");
      toast("Ошибка сохранения config.toml.", "error", 2200);
    }
  });
}

async function initNetworkForm(state) {
  const data = await fetchJson("/api/net/ifaces");
  if (!data) return;
  const ifaces = data.ifaces || [];
  state.ifaces = ifaces;

  initSelectPairs("egressDev", "egressIp", "egressGw", ifaces, state.egressDev || "");
  initSelectPairs("ingressDev", "ingressIp", "ingressGw", ifaces, state.ingressDev || "");

  try {
    const saved = await fetchJson("/api/net/routing-config");
    const cfg = saved && saved.config ? saved.config : {};
    if (cfg.egress_dev) {
      $("egressDev").value = cfg.egress_dev;
      $("egressDev").dispatchEvent(new Event("change"));
    }
    if (cfg.egress_ip) $("egressIp").value = cfg.egress_ip;
    if (typeof cfg.egress_gw === "string") $("egressGw").value = cfg.egress_gw;
    if (cfg.ingress_dev) {
      $("ingressDev").value = cfg.ingress_dev;
      $("ingressDev").dispatchEvent(new Event("change"));
    }
    if (cfg.ingress_ip) $("ingressIp").value = cfg.ingress_ip;
    if (typeof cfg.ingress_gw === "string") $("ingressGw").value = cfg.ingress_gw;
    if (cfg.route_mode) state.routeMode = cfg.route_mode;
    refreshInterfaceStatuses(saved && saved.runtime ? saved.runtime : null);
  } catch {
    // no saved routing config yet
  }
}

function refreshInterfaceStatuses(runtime) {
  const rt = runtime || {};
  if (!rt || typeof rt !== "object" || !("applied" in rt)) {
    setStatusById("egressStatus", "dot--warn", "не применено");
    setStatusById("ingressStatus", "dot--warn", "не применено");
    return;
  }
  if (rt.egress_ok) {
    setStatusById("egressStatus", "dot--ok", "применено");
  } else {
    setStatusById("egressStatus", "dot--bad", "не применено");
  }
  if (!rt.ingress_enabled) {
    setStatusById("ingressStatus", "dot--unknown", "не требуется (ingress=egress)");
    return;
  }
  if (rt.ingress_ok) {
    setStatusById("ingressStatus", "dot--ok", "применено");
  } else {
    setStatusById("ingressStatus", "dot--bad", "не применено");
  }
}

function initInterfaceSave() {
  $("ifaceSaveBtn").addEventListener("click", async () => {
    const btn = $("ifaceSaveBtn");
    const body = {
      egress_dev: $("egressDev").value,
      egress_ip: $("egressIp").value,
      egress_gw: $("egressGw").value.trim(),
      ingress_dev: $("ingressDev").value,
      ingress_ip: $("ingressIp").value,
      ingress_gw: $("ingressGw").value.trim(),
      route_mode: window.__awgState && window.__awgState.routeMode ? window.__awgState.routeMode : "egress",
    };
    if (!body.egress_dev || !body.egress_ip) {
      toast("Нужно выбрать egress интерфейс и IPv4.", "error", 2200);
      return;
    }
    try {
      btn.disabled = true;
      const res = await postJson("/api/net/routing/save", body);
      refreshInterfaceStatuses(res && res.runtime ? res.runtime : null);
      toast("Сохранено успешно. Маршрутизация применена.", "ok");
    } catch (e) {
      setStatusById("egressStatus", "dot--bad", "ошибка применения");
      setStatusById("ingressStatus", "dot--bad", "ошибка применения");
      toast(`Ошибка применения: ${e?.message || "unknown"}`, "error", 2600);
    } finally {
      btn.disabled = false;
    }
  });
}

function initNetplanEditor() {
  const overlay = $("netplanModalOverlay");
  const text = $("netplanText");
  const hint = $("netplanPathHint");
  const errHint = $("netplanErrorHint");

  const close = () => {
    overlay.classList.add("hidden");
    errHint.textContent = "";
  };

  $("netplanOpenBtn").addEventListener("click", async () => {
    try {
      const res = await fetchJson("/api/netplan/config");
      if (!res) return;
      text.value = String(res.config_text || "");
      hint.textContent = `Файл: ${res.path || "—"}`;
      errHint.textContent = "";
      overlay.classList.remove("hidden");
    } catch (e) {
      toast(`Ошибка чтения netplan: ${e?.message || "unknown"}`, "error", 2600);
    }
  });

  $("netplanModalCloseBtn").addEventListener("click", close);
  $("netplanModalCancelBtn").addEventListener("click", close);
  overlay.addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "netplanModalOverlay") close();
  });

  $("netplanSaveBtn").addEventListener("click", async () => {
    const btn = $("netplanSaveBtn");
    try {
      btn.disabled = true;
      errHint.textContent = "";
      await postJson("/api/netplan/validate", { config_text: text.value });
      const res = await postJson("/api/netplan/save", { config_text: text.value });
      hint.textContent = `Файл: ${res.path || "—"}`;
      toast("Netplan сохранен и применен.", "ok", 2200);
      close();
    } catch (e) {
      const msg = e?.message || "unknown";
      errHint.textContent = msg;
      toast("Ошибка синтаксиса/применения netplan.", "error", 3200);
    } finally {
      btn.disabled = false;
    }
  });
}

function routeModeLabel(mode) {
  if (mode === "tunnel") return "в тунельный интерфейс";
  if (mode === "georouting") return "georouting";
  return "в egress";
}

function initRoutingPanel(state) {
  const root = $("routingModes");
  const geoFieldset = $("geoRoutingFieldset");
  const geoTarget = $("geoRouteTarget");
  const geoIpModeBtn = $("geoIpModeBtn");
  const geoDomainModeBtn = $("geoDomainModeBtn");
  const geoListModalOverlay = $("geoListModalOverlay");
  const geoListModalTitle = $("geoListModalTitle");
  const geoListText = $("geoListText");
  const geoLists = {
    ipInclude: $("geoEditIpIncludeBtn"),
    ipExclude: $("geoEditIpExcludeBtn"),
    domainInclude: $("geoEditDomainIncludeBtn"),
    domainExclude: $("geoEditDomainExcludeBtn"),
  };
  const geoReady = {
    ipStatus: $("geoIpReadyStatus"),
    domainStatus: $("geoDomainReadyStatus"),
    ipAdd: $("geoIpReadyAddBtn"),
    domainAdd: $("geoDomainReadyAddBtn"),
  };
  const geoReadyModal = {
    overlay: $("geoReadyModalOverlay"),
    title: $("geoReadyModalTitle"),
    list: $("geoReadyList"),
    input: $("geoReadyNewUrl"),
    addBtn: $("geoReadyAddBtn"),
    hint: $("geoReadyModalHint"),
  };
  const closeGeoReadyModal = () => geoReadyModal.overlay.classList.add("hidden");

  function refreshReadyStatus(kind) {
    const isIp = kind === "ip";
    const links = isIp ? state.geo.readyLinks.ip : state.geo.readyLinks.domain;
    const rootId = isIp ? "geoIpReadyStatus" : "geoDomainReadyStatus";
    const total = links.length;
    if (!links.length) {
      setStatusById(rootId, "dot--unknown", "Списков: 0, активных 0");
      return;
    }
    const enabledCount = links.filter((x) => x && x.enabled !== false).length;
    const checkingCount = links.filter(
      (x) => x && x.enabled !== false && (x.status === "на проверке" || x.status === "ожидает проверки")
    ).length;
    const errCount = links.filter((x) => x && x.enabled !== false && x.status === "с ошибкой").length;

    // Priority order from user:
    // 1) all active & checked => green
    // 2) any error => yellow (except all errors => red)
    // 3) any checking => yellow
    // 4) all active are errors => red
    if (enabledCount > 0 && checkingCount === 0 && errCount === 0) {
      setStatusById(rootId, "dot--ok", `Списков: ${total}, активных ${enabledCount}`);
      return;
    }
    if (enabledCount > 0 && errCount === enabledCount) {
      setStatusById(rootId, "dot--bad", `Списков: ${total}, активных 0, с ошибкой ${errCount}`);
      return;
    }
    if (errCount > 0) {
      setStatusById(
        rootId,
        "dot--warn",
        `Списков: ${total}, активных ${Math.max(0, enabledCount - errCount)}, с ошибкой ${errCount}`
      );
      return;
    }
    if (checkingCount > 0) {
      setStatusById(
        rootId,
        "dot--warn",
        `Списков: ${total}, активных ${Math.max(0, enabledCount - checkingCount)}, на проверке ${checkingCount}`
      );
    } else {
      setStatusById(rootId, "dot--unknown", `Списков: ${total}, активных ${enabledCount}`);
    }
  }

  function refreshGeoUi() {
    const geoSelected = state.routeMode === "georouting";
    geoFieldset.disabled = !geoSelected;
    if (!geoSelected) {
      setStatusById("geoRoutingStatus", "dot--unknown", "выберите режим georouting");
    } else {
      setStatusById("geoRoutingStatus", "dot--warn", "не применено");
    }

    geoTarget.value = state.geo.target;
    geoIpModeBtn.classList.toggle("is-on", Boolean(state.geo.ipMode));
    geoDomainModeBtn.classList.toggle("is-on", Boolean(state.geo.domainMode));
    geoIpModeBtn.setAttribute("aria-pressed", state.geo.ipMode ? "true" : "false");
    geoDomainModeBtn.setAttribute("aria-pressed", state.geo.domainMode ? "true" : "false");

    geoIpModeBtn.disabled = !geoSelected;
    geoDomainModeBtn.disabled = !geoSelected;
    geoLists.ipInclude.disabled = !(geoSelected && state.geo.ipMode);
    geoLists.ipExclude.disabled = !(geoSelected && state.geo.ipMode);
    geoLists.domainInclude.disabled = !(geoSelected && state.geo.domainMode);
    geoLists.domainExclude.disabled = !(geoSelected && state.geo.domainMode);
    geoReady.ipAdd.disabled = !(geoSelected && state.geo.ipMode);
    geoReady.domainAdd.disabled = !(geoSelected && state.geo.domainMode);
    refreshReadyStatus("ip");
    refreshReadyStatus("domain");
  }

  function openGeoListModal(kind) {
    const titles = {
      ipInclude: "Включить IP",
      ipExclude: "Исключить IP",
      domainInclude: "Включить домен",
      domainExclude: "Исключить домен",
    };
    state.geo.editingList = kind;
    geoListModalTitle.textContent = titles[kind] || "Правка списка";
    geoListText.value = state.geo.lists[kind] || "";
    geoListModalOverlay.classList.remove("hidden");
  }

  function readyEntries(kind) {
    const list = kind === "ip" ? state.geo.readyLinks.ip : state.geo.readyLinks.domain;
    for (let i = 0; i < list.length; i += 1) {
      if (typeof list[i] === "string") {
        list[i] = { url: list[i], status: "ожидает проверки", enabled: true, protected: false };
      }
    }
    return list;
  }

  function renderReadyModal(kind) {
    const entries = readyEntries(kind);
    geoReadyModal.list.innerHTML = "";
    if (!entries.length) {
      const empty = document.createElement("div");
      empty.className = "help";
      empty.textContent = "Списки не добавлены.";
      geoReadyModal.list.appendChild(empty);
      return;
    }
    for (const it of entries) {
      const enabled = it.enabled !== false;
      const statusText = enabled ? it.status || "на проверке" : "выключен (не проверяется)";
      const isProtected = Boolean(it.protected);
      const row = document.createElement("div");
      row.className = "geo-ready-item";
      row.innerHTML = `
        <div class="geo-ready-url">${it.url || ""}</div>
        <div class="geo-ready-status">${statusText}</div>
        <button class="switch geo-switch ${enabled ? "is-on" : ""}" data-toggle-ready="${it.url || ""}" type="button" title="${enabled ? "Выключить" : "Включить"}"></button>
        <button class="mini-btn mini-btn--danger" data-del-ready="${it.url || ""}" type="button" ${isProtected ? "disabled" : ""}>-</button>
      `;
      geoReadyModal.list.appendChild(row);
    }
  }

  function openReadyModal(kind) {
    state.geo.editingReadyKind = kind;
    geoReadyModal.title.textContent = kind === "ip" ? "Готовые списки IP" : "Готовые списки доменов";
    geoReadyModal.hint.textContent =
      kind === "ip"
        ? "Требуется URL до списка в формате .lst: один IP/сеть в одной строке."
        : "Требуется URL до списка в формате .lst: один домен в одной строке.";
    geoReadyModal.input.value = "";
    renderReadyModal(kind);
    geoReadyModal.overlay.classList.remove("hidden");
  }

  function closeGeoListModal() {
    geoListModalOverlay.classList.add("hidden");
  }

  const applyMode = async (mode, options = {}) => {
    if (!state.tunnelUp) {
      setStatusById("routingModeStatus", "dot--ok", "маршрутизируем в egress (по умолчанию)");
      return;
    }
    if (mode === "georouting") {
      state.routeMode = mode;
      for (const btn of root.querySelectorAll(".routing-mode-btn")) {
        const active = btn.getAttribute("data-route-mode") === mode;
        btn.classList.toggle("is-active", active);
      }
      setStatusById("routingModeStatus", "dot--warn", "georouting: пока не применено");
      refreshGeoUi();
      return;
    }
    setRouteModeStatus(mode, false);
    try {
      const res = await postJson("/api/net/routing/mode", { route_mode: mode });
      state.routeMode = (res && res.config && res.config.route_mode) || mode;
      for (const btn of root.querySelectorAll(".routing-mode-btn")) {
        const active = btn.getAttribute("data-route-mode") === state.routeMode;
        btn.classList.toggle("is-active", active);
      }
      setRouteModeStatus(state.routeMode, true);
      if (!options.silent) toast(state.routeMode === "tunnel" ? "Режим туннеля применен." : "Режим egress применен.", "ok");
      refreshGeoUi();
    } catch (e) {
      setRouteModeStatus(mode, false);
      if (!options.silent) toast(`Ошибка применения режима: ${e?.message || "unknown"}`, "error", 2800);
    }
  };

  root.addEventListener("click", (ev) => {
    if (!state.tunnelUp) return;
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    const btn = t.closest(".routing-mode-btn");
    if (!(btn instanceof HTMLElement)) return;
    const mode = btn.getAttribute("data-route-mode") || "egress";
    applyMode(mode);
  });

  geoTarget.addEventListener("change", () => {
    state.geo.target = geoTarget.value || "tunnel";
  });
  geoIpModeBtn.addEventListener("click", () => {
    if (state.routeMode !== "georouting") return;
    state.geo.ipMode = !state.geo.ipMode;
    refreshGeoUi();
  });
  geoDomainModeBtn.addEventListener("click", () => {
    if (state.routeMode !== "georouting") return;
    state.geo.domainMode = !state.geo.domainMode;
    refreshGeoUi();
  });

  geoLists.ipInclude.addEventListener("click", () => openGeoListModal("ipInclude"));
  geoLists.ipExclude.addEventListener("click", () => openGeoListModal("ipExclude"));
  geoLists.domainInclude.addEventListener("click", () => openGeoListModal("domainInclude"));
  geoLists.domainExclude.addEventListener("click", () => openGeoListModal("domainExclude"));
  $("geoListModalCloseBtn").addEventListener("click", closeGeoListModal);
  $("geoListCancelBtn").addEventListener("click", closeGeoListModal);
  geoListModalOverlay.addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "geoListModalOverlay") closeGeoListModal();
  });
  $("geoListSaveBtn").addEventListener("click", () => {
    const key = state.geo.editingList;
    if (!key) return;
    state.geo.lists[key] = geoListText.value || "";
    closeGeoListModal();
    toast("Список сохранен (локально).", "ok");
  });

  function addReadyLink(kind) {
    const url = (geoReadyModal.input.value || "").trim();
    if (!url) return;
    if (!/^https?:\/\//i.test(url)) {
      toast("Нужен URL, начинающийся с http:// или https://", "error", 2200);
      return;
    }
    const target = readyEntries(kind);
    const isLst = /\.lst($|\?)/i.test(url);
    target.push({ url, status: isLst ? "на проверке" : "с ошибкой" });
    geoReadyModal.input.value = "";
    refreshReadyStatus(kind);
    renderReadyModal(kind);
    toast("Список добавлен.", "ok");
  }
  geoReady.ipAdd.addEventListener("click", () => openReadyModal("ip"));
  geoReady.domainAdd.addEventListener("click", () => openReadyModal("domain"));
  $("geoReadyModalCloseBtn").addEventListener("click", closeGeoReadyModal);
  $("geoReadyModalCloseBtn2").addEventListener("click", closeGeoReadyModal);
  geoReadyModal.overlay.addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "geoReadyModalOverlay") closeGeoReadyModal();
  });
  geoReadyModal.addBtn.addEventListener("click", () => {
    const kind = state.geo.editingReadyKind || "ip";
    addReadyLink(kind);
  });
  geoReadyModal.list.addEventListener("click", (ev) => {
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    const toggleUrl = t.getAttribute("data-toggle-ready");
    if (toggleUrl) {
      const kind = state.geo.editingReadyKind || "ip";
      const target = readyEntries(kind);
      const item = target.find((x) => String(x.url || "") === toggleUrl);
      if (item) {
        item.enabled = item.enabled === false;
        if (item.enabled !== false && item.status !== "с ошибкой") item.status = "на проверке";
        refreshReadyStatus(kind);
        renderReadyModal(kind);
      }
      return;
    }
    const url = t.getAttribute("data-del-ready");
    if (!url) return;
    const kind = state.geo.editingReadyKind || "ip";
    const target = readyEntries(kind);
    const idx = target.findIndex((x) => String(x.url || "") === url);
    if (idx >= 0) {
      target.splice(idx, 1);
      refreshReadyStatus(kind);
      renderReadyModal(kind);
      toast("Список удален.", "ok");
    }
  });

  const startMode = state.routeMode || "egress";
  for (const btn of root.querySelectorAll(".routing-mode-btn")) {
    const active = btn.getAttribute("data-route-mode") === startMode;
    btn.classList.toggle("is-active", active);
  }
  if (!state.tunnelUp) {
    setStatusById("routingModeStatus", "dot--ok", "маршрутизируем в egress (по умолчанию)");
  } else if (startMode === "georouting") {
    setStatusById("routingModeStatus", "dot--warn", "georouting: пока не применено");
  } else {
    setRouteModeStatus(startMode, true);
  }
  refreshGeoUi();
}

async function logout() {
  await fetch(`${basePath()}api/auth/logout`, { method: "POST", credentials: "include" }).catch(() => {});
  window.location.href = `${basePath()}login.html`;
}

async function main() {
  const state = {
    confText: "",
    importMode: "",
    prevCpu: null,
    prevNet: null,
    mtproto: null,
    tunnelUp: false,
    routeMode: "egress",
    geo: {
      target: "tunnel",
      ipMode: false,
      domainMode: false,
      editingList: "",
      editingReadyKind: "",
      readyLinks: {
        ip: [
          {
            url: "https://antifilter.download/list/allyouneed.lst",
            status: "ожидает проверки",
            enabled: true,
            protected: true,
          },
        ],
        domain: [
          {
            url: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
            status: "ожидает проверки",
            enabled: true,
            protected: true,
          },
        ],
      },
      lists: { ipInclude: "", ipExclude: "", domainInclude: "", domainExclude: "" },
    },
  };
  window.__awgState = state;

  const authEnabled = Boolean(window.__AWG_AUTH_ENABLED__);
  if (authEnabled) {
    $("logoutBtn").addEventListener("click", logout);
  } else {
    $("logoutBtn").style.display = "none";
  }

  initImportModal(state);
  initMtprotoPanel(state);
  initInterfaceSave();
  initNetplanEditor();

  await initNetworkForm(state);
  await refreshTunnelStatus(state);
  initRoutingPanel(state);
  await refreshSystemMetrics(state);
  await refreshMtprotoState(state);
  setInterval(() => refreshTunnelStatus(state), 5000);
  setInterval(() => refreshSystemMetrics(state), 2000);
  setInterval(() => refreshMtprotoState(state), 5000);
}

window.addEventListener("DOMContentLoaded", main);

