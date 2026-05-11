function $(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element: #${id}`);
  return el;
}

let __busyOverlayCounter = 0;
let __reconnectToastVisible = false;
let __reconnectNoticeVisible = false;

function ensureBusyOverlay() {
  let root = document.getElementById("busyOverlay");
  if (root) return root;
  root = document.createElement("div");
  root.id = "busyOverlay";
  root.className = "busy-overlay hidden";
  root.setAttribute("aria-live", "polite");
  root.innerHTML = `
    <div class="busy-overlay-card" role="status" aria-label="Выполняется">
      <div class="busy-spinner" aria-hidden="true"></div>
      <div class="busy-text" id="busyOverlayText">Выполняется…</div>
    </div>
  `;
  document.body.appendChild(root);
  return root;
}

function showBusyOverlay(text = "Выполняется…") {
  const root = ensureBusyOverlay();
  const label = root.querySelector("#busyOverlayText");
  if (label) label.textContent = text;
  __busyOverlayCounter += 1;
  root.classList.remove("hidden");
}

function hideBusyOverlay() {
  const root = document.getElementById("busyOverlay");
  if (!root) return;
  __busyOverlayCounter = Math.max(0, __busyOverlayCounter - 1);
  if (__busyOverlayCounter === 0) root.classList.add("hidden");
}

function setBusyOverlayText(text = "Выполняется…") {
  const root = document.getElementById("busyOverlay");
  const label = root && root.querySelector("#busyOverlayText");
  if (label) label.textContent = text;
}

async function withBusyOverlay(text, fn) {
  showBusyOverlay(text);
  try {
    return await fn();
  } finally {
    hideBusyOverlay();
  }
}

function basePath() {
  return (window.__AWG_BASE_PATH__ || "/").replace(/\/?$/, "/");
}

function applyAppVersionLabels(metricsVersion) {
  const fromWindow =
    typeof window.__AWG_APP_VERSION__ === "string" ? window.__AWG_APP_VERSION__.trim() : "";
  const fromMetrics =
    typeof metricsVersion === "string" && metricsVersion.trim() ? metricsVersion.trim() : "";
  const v = fromMetrics || fromWindow;
  const label = v ? `Версия ${v}` : "";
  const foot = document.getElementById("footerAppVersion");
  if (foot) foot.textContent = label;
}

/** Session expired or server restarted in-memory sessions — send user to login. */
function redirectToWebUiLogin() {
  try {
    const next = encodeURIComponent(`${window.location.pathname}${window.location.search || ""}`);
    window.location.href = `${basePath()}login.html?next=${next}`;
  } catch {
    window.location.href = `${basePath()}login.html`;
  }
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

function fmtUnixLocal(ts) {
  const n = Number(ts);
  if (!n || Number.isNaN(n)) return "";
  try {
    return new Date(n * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
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
  dot.classList.remove("dot--unknown", "dot--ok", "dot--warn", "dot--bad", "dot--muted");
  dot.classList.add(kind);
  statusText.textContent = text;
}

function setStatusById(rootId, kind, text) {
  const root = document.getElementById(rootId);
  if (!root) return;
  const dot = root.querySelector(".dot");
  const statusText = root.querySelector(".status-text");
  if (!dot || !statusText) return;
  dot.classList.remove("dot--unknown", "dot--ok", "dot--warn", "dot--bad", "dot--muted");
  dot.classList.add(kind);
  statusText.textContent = text;
}

function setHealthRowStatus(statusId, kind, text) {
  setStatusById(statusId, kind, text);
  const root = document.getElementById(statusId);
  if (!root) return;
  const row = root.closest(".mt-health-row");
  if (!row) return;
  row.classList.remove(
    "mt-health-row--ok",
    "mt-health-row--warn",
    "mt-health-row--bad",
    "mt-health-row--unknown",
    "mt-health-row--muted"
  );
  const tone = kind.replace(/^dot--/, "");
  if (tone === "ok" || tone === "warn" || tone === "bad" || tone === "unknown" || tone === "muted") {
    row.classList.add(`mt-health-row--${tone}`);
  }
}

function systemdStateRu(s) {
  const x = String(s || "").trim().toLowerCase();
  if (x === "active") return "активен";
  if (x === "inactive") return "не активен";
  if (x === "enabled") return "включён";
  if (x === "disabled") return "выключен";
  if (x === "failed") return "ошибка";
  if (x === "unknown") return "неизвестно";
  if (!x) return "неизвестно";
  return String(s);
}

function ruUsersCount(n) {
  const k = Math.abs(Number(n) || 0);
  const mod10 = k % 10;
  const mod100 = k % 100;
  if (mod10 === 1 && mod100 !== 11) return `${k} пользователь`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return `${k} пользователя`;
  return `${k} пользователей`;
}

/** Список причин, почему masking_health.ok === false (для текста в шапке карточки). */
function maskingIssueSummaryLines(mh) {
  const issues = [];
  const epOk = mh.endpoint_ok === true || String(mh.endpoint_status || "").toUpperCase() === "OK";
  if (!epOk) issues.push("конечная точка недоступна");
  const ngx = mh.nginx || {};
  if (ngx.ok === false) issues.push("Nginx не в норме");
  const tm = mh.health_timer || {};
  if (tm.ok === false) issues.push("таймер health не в норме");
  if (mh.mask_port_open_local === false) issues.push("локальный порт маскировки недоступен");
  return issues;
}

function maskingIssueSummaryText(mh) {
  const issues = maskingIssueSummaryLines(mh);
  return issues.length ? issues.join(" · ") : "не все проверки пройдены (см. строки ниже)";
}

const AMNEZIA_DNS_MISSING_MSG =
  "Отсутствует сервис AmneziaDNS — установите его на сервер из приложения AmneziaVPN.";
const AMNEZIA_DNS_GEO_HINT = "Отсутствует сервис AmneziaDNS смотри настройку DNS";

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

function initWebUiUpdateBanner() {
  const overlay = $("webuiUpdateModalOverlay");
  const applyBtn = $("webuiUpdateModalApplyBtn");
  const blockedHint = $("webuiUpdateBlockedHint");

  function syncApplyEnabled() {
    const inf = window.__awgUpdateInfo || {};
    const err = String(inf.checkError || "").trim();
    const ok = Boolean(inf.canApply) && !err;
    applyBtn.disabled = !ok;
    const parts = [];
    if (err) parts.push(`Проверка версии: ${err}`);
    if (!inf.canApply && inf.blocked) parts.push(inf.blocked);
    if (parts.length) {
      blockedHint.textContent = parts.join(" ");
      blockedHint.hidden = false;
    } else {
      blockedHint.textContent = "";
      blockedHint.hidden = true;
    }
  }

  function openWebUiUpdateModal() {
    const inf = window.__awgUpdateInfo || {};
    $("webuiUpdateCurrentVer").textContent = inf.current || "—";
    $("webuiUpdateLatestVer").textContent = inf.latest || "—";
    $("webuiUpdateRepoLabel").textContent = inf.repo || "—";
    $("webuiUpdateBranchLabel").textContent = inf.branch || "main";
    syncApplyEnabled();
    overlay.classList.remove("hidden");
    overlay.setAttribute("aria-hidden", "false");
    applyBtn.focus();
  }

  function closeWebUiUpdateModal() {
    overlay.classList.add("hidden");
    overlay.setAttribute("aria-hidden", "true");
  }

  $("updateNoticeDetailsBtn").addEventListener("click", openWebUiUpdateModal);
  $("webuiUpdateModalCloseBtn").addEventListener("click", closeWebUiUpdateModal);
  $("webuiUpdateModalCancelBtn").addEventListener("click", closeWebUiUpdateModal);
  overlay.addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "webuiUpdateModalOverlay") closeWebUiUpdateModal();
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && !overlay.classList.contains("hidden")) closeWebUiUpdateModal();
  });

  $("webuiUpdateModalApplyBtn").addEventListener("click", async () => {
    if (applyBtn.disabled) return;
    closeWebUiUpdateModal();
    try {
      await withBusyOverlay("Загрузка и обновление (это может занять несколько минут)…", async () => {
        await postJsonAwaitTask("/api/update/start", {}, 50 * 60 * 1000);
      });
      toast("Обновление завершено. Панель перезапускается…", "ok", 4500);
      setTimeout(() => {
        window.location.reload();
      }, 6500);
    } catch (e) {
      const msg = String((e && e.message) || e || "ошибка");
      if (/fetch|network|failed/i.test(msg)) {
        toast("Соединение прервалось — если обновление уже шло, подождите и обновите страницу (F5).", "warn", 7000);
      } else {
        toast(msg, "err", 9000);
      }
    }
  });
}

function initAmneziaSetupBanner() {
  const overlay = $("amneziaSetupModalOverlay");
  function openAmneziaSetupModal() {
    overlay.classList.remove("hidden");
    overlay.setAttribute("aria-hidden", "false");
    $("amneziaSetupModalOkBtn").focus();
  }
  function closeAmneziaSetupModal() {
    overlay.classList.add("hidden");
    overlay.setAttribute("aria-hidden", "true");
  }
  $("amneziaSetupDetailsBtn").addEventListener("click", openAmneziaSetupModal);
  $("amneziaSetupModalCloseBtn").addEventListener("click", closeAmneziaSetupModal);
  $("amneziaSetupModalOkBtn").addEventListener("click", closeAmneziaSetupModal);
  overlay.addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "amneziaSetupModalOverlay") closeAmneziaSetupModal();
  });
  window.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    if (overlay.classList.contains("hidden")) return;
    closeAmneziaSetupModal();
  });
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
      setTunnelStatus("dot--warn", "Туннель awg-uplink: импорт конфигурации");
      await withBusyOverlay("Импортируем конфигурацию туннеля…", async () => {
        await postJson("/api/tunnel/validate", { config_text: cfgText });
        await postJson("/api/tunnel/import", { config_text: cfgText });
      });
      toast("Конфиг туннеля awg-uplink импортирован.", "ok");
      await refreshTunnelStatus(state);
    } catch (e) {
      setTunnelStatus("dot--bad", "Туннель awg-uplink: ошибка импорта");
      toast(`Ошибка импорта: ${e?.message || "unknown"}`, "error", 3000);
    }
  });

  restartBtn.addEventListener("click", async () => {
    try {
      setTunnelStatus("dot--warn", "Туннель awg-uplink: перезапуск");
      await withBusyOverlay("Перезапускаем туннель…", async () => {
        await postJson("/api/tunnel/restart", {});
      });
      toast("Туннель awg-uplink перезапущен.", "ok");
      await refreshTunnelStatus(state);
    } catch (e) {
      setTunnelStatus("dot--bad", "Туннель awg-uplink: ошибка перезапуска");
      toast(`Ошибка перезапуска: ${e?.message || "unknown"}`, "error", 2800);
    }
  });

  render();
}

async function fetchJson(path) {
  const res = await fetchWithReconnect(`${basePath()}${path.replace(/^\//, "")}`, { credentials: "include" }, { retries: 12, delayMs: 1000 });
  if (res.status === 401) {
    redirectToWebUiLogin();
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
  } else if (mode === "georouting") {
    setStatusById("routingModeStatus", "dot--ok", "georouting: применено");
  } else {
    setStatusById("routingModeStatus", "dot--warn", `не применено: ${routeModeLabel(mode)}`);
  }
}

function isInterfaceConfigReady(cfg) {
  if (!cfg || typeof cfg !== "object") return false;
  return Boolean(String(cfg.egress_dev || "").trim() && String(cfg.egress_ip || "").trim());
}

function setInterfaceConfigGateLocked(locked) {
  const gate = document.getElementById("ifaceConfigGate");
  const overlay = document.getElementById("ifaceConfigGateOverlay");
  if (!gate || !overlay) return;
  gate.classList.toggle("is-locked", Boolean(locked));
  overlay.classList.toggle("hidden", !locked);
}

async function refreshTunnelStatus(state = null) {
  try {
    const st = await fetchJson("/api/status/awg-uplink");
    if (!st) return;
    const up = Boolean(st.exists && st.state === "UP");
    if (state) state.tunnelUp = up;
    setRoutingAvailability(up);
    if (!st.exists)
      return setTunnelStatus("dot--bad", st.configured ? "Туннель awg-uplink: DOWN" : "Туннель awg-uplink: не настроен");
    const op = st.operstate && st.operstate !== "UNKNOWN" ? st.operstate : "";
    if (st.state === "UP") return setTunnelStatus("dot--ok", `Туннель awg-uplink: UP${op ? ` (${op})` : ""}`);
    const base = st.state || "UNKNOWN";
    return setTunnelStatus("dot--warn", `Туннель awg-uplink: ${base}${op ? ` (${op})` : ""}`);
  } catch {
    if (state) state.tunnelUp = false;
    setRoutingAvailability(false);
    setTunnelStatus("dot--unknown", "Туннель awg-uplink: ошибка статуса");
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

    const notice = $("amneziaSetupNotice");
    notice.classList.toggle("hidden", m.amnezia_setup_banner !== true);

    const updNotice = $("updateAvailableNotice");
    const curV = m.update_current_version;
    const latV = m.update_latest_version;
    const updAvail =
      m.update_check_enabled !== false &&
      Boolean(m.update_available) &&
      !(m.update_check_error && String(m.update_check_error).trim());
    updNotice.classList.toggle("hidden", !updAvail);
    if (updAvail) {
      $("updateNoticeVersionBrief").textContent = `${curV || "?"} → ${latV || "?"}`;
    }
    window.__awgUpdateInfo = {
      current: curV,
      latest: latV,
      repo: m.update_repo,
      branch: m.update_branch,
      canApply: Boolean(m.update_can_apply),
      blocked: m.update_apply_blocked_reason || "",
      checkError: m.update_check_error || "",
    };
    applyAppVersionLabels(m.update_current_version);

    const fwToggle = document.getElementById("ifaceFwEnabled");
    if (
      fwToggle &&
      typeof m.iface_firewall_enabled === "boolean" &&
      state &&
      !state.ifaceFwSyncDirty
    ) {
      fwToggle.checked = m.iface_firewall_enabled;
    }
  } catch {
    // keep last values on temporary errors
  }
}

function isTransientFetchError(err) {
  const msg = String((err && err.message) || err || "").toLowerCase();
  return msg.includes("failed to fetch") || msg.includes("networkerror") || msg.includes("network error");
}

async function fetchWithReconnect(url, options = {}, cfg = {}) {
  const retries = Math.max(0, Number(cfg.retries) || 0);
  const delayMs = Math.max(100, Number(cfg.delayMs) || 1000);
  const retryStatuses = Array.isArray(cfg.retryStatuses) ? cfg.retryStatuses : [502, 503, 504];
  const showReconnectToast = cfg.showReconnectToast !== false;
  let reconnectNotified = false;
  const showReconnectNotice = cfg.showReconnectNotice !== false;
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(url, options);
      if (res.status === 401) return res;
      if (retryStatuses.includes(res.status) && attempt < retries) {
        if (showReconnectNotice) showReconnectNoticeBanner();
        if (showReconnectToast && !reconnectNotified && !__reconnectToastVisible) {
          __reconnectToastVisible = true;
          reconnectNotified = true;
          toast("Соединение временно прервано, пытаемся переподключиться…", "warn", Math.max(2500, delayMs + 1200));
        }
        await sleepMs(delayMs);
        continue;
      }
      if (reconnectNotified) __reconnectToastVisible = false;
      hideReconnectNoticeBanner();
      return res;
    } catch (e) {
      if (attempt >= retries || !isTransientFetchError(e)) throw e;
      if (showReconnectNotice) showReconnectNoticeBanner();
      if (showReconnectToast && !reconnectNotified && !__reconnectToastVisible) {
        __reconnectToastVisible = true;
        reconnectNotified = true;
        toast("Соединение временно прервано, пытаемся переподключиться…", "warn", Math.max(2500, delayMs + 1200));
      }
      await sleepMs(delayMs);
    }
  }
}

async function postJson(path, body, retryCfg = null) {
  const res = await fetchWithReconnect(
    `${basePath()}${path.replace(/^\//, "")}`,
    {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body || {}),
    },
    retryCfg || { retries: 0 }
  );
  if (res.status === 401) {
    redirectToWebUiLogin();
    throw new Error("Unauthorized");
  }
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  return res.json().catch(() => ({}));
}

async function sleepMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function postJsonAwaitTask(path, body, timeoutMs = 20 * 60 * 1000) {
  const started = await postJson(path, body, { retries: 5, delayMs: 1200, retryStatuses: [502, 503, 504] });
  const taskId = started && started.task_id;
  if (!taskId) return started;
  const t0 = Date.now();
  while (true) {
    const st = await fetchJson(`/api/op/status?task_id=${encodeURIComponent(taskId)}`);
    if (!st || st.running !== true) {
      if (st && st.ok === false) throw new Error(st.error || "operation failed");
      return (st && st.result) || {};
    }
    if (Date.now() - t0 > timeoutMs) throw new Error("Превышено время ожидания выполнения операции.");
    await sleepMs(2000);
  }
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

function setMtprotoPanelLocked(locked) {
  const root = document.getElementById("mtprotoPanelRoot");
  if (!root) return;
  root.classList.toggle("mtproto-panel--locked", Boolean(locked));
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

function showReconnectNoticeBanner() {
  let el = document.getElementById("reconnectNotice");
  if (!el) {
    el = document.createElement("div");
    el.id = "reconnectNotice";
    el.className = "reconnect-notice hidden";
    el.setAttribute("aria-live", "polite");
    el.innerHTML = `
      <div class="reconnect-notice__spinner" aria-hidden="true"></div>
      <div class="reconnect-notice__text">Соединение временно прервано, пытаемся переподключиться…</div>
    `;
    document.body.appendChild(el);
  }
  __reconnectNoticeVisible = true;
  el.classList.remove("hidden");
}

function hideReconnectNoticeBanner() {
  __reconnectNoticeVisible = false;
  const el = document.getElementById("reconnectNotice");
  if (el) el.classList.add("hidden");
}

/** Drop mtproto toggle pending entries once /api/mtproto/state matches expected enabled per user. */
function reconcileMtprotoPendingToggles(users, pending) {
  if (!pending || typeof pending !== "object") return;
  const list = users || [];
  for (const uname of Object.keys(pending)) {
    const req = pending[uname];
    if (!req || typeof req.enabled !== "boolean") continue;
    const row = list.find((u) => String(u.username || "") === String(uname));
    if (!row) continue;
    if (Boolean(row.enabled) === Boolean(req.enabled)) {
      delete pending[uname];
    }
  }
}

function renderMtprotoUsers(users, pendingToggles = {}) {
  const body = $("mtpUsersBody");
  body.innerHTML = "";
  const enabledCount = users.filter((u) => Boolean(u && u.enabled)).length;
  for (const u of users) {
    const row = document.createElement("div");
    row.className = "mtp-user-item";
    const link = u.link || "";
    const pending = pendingToggles && pendingToggles[u.username || ""];
    const baseEnabled = Boolean(u.enabled);
    const enabled = pending ? Boolean(pending.enabled) : baseEnabled;
    const lastActiveLock = baseEnabled && enabledCount <= 1;
    const sessions = Number(u.sessions || 0);
    const linkTme = u.link_tme || tgToTme(link);
    row.innerHTML = `
      <button class="switch ${enabled ? "is-on" : ""}" data-toggle-user="${u.username || ""}" data-enabled="${enabled ? "1" : "0"}" type="button" ${pending || lastActiveLock ? "disabled" : ""} title="${pending ? "Применяется..." : lastActiveLock ? "Нельзя выключить последнего активного пользователя" : enabled ? "Выключить" : "Включить"}"></button>
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
        <button class="mini-btn mini-btn--danger user-action" data-del-user="${u.username || ""}" type="button" ${lastActiveLock ? "disabled" : ""} title="${lastActiveLock ? "Нельзя удалить последнего активного пользователя" : "Удалить"}">✕</button>
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
    const mtpCfgOverlay = $("mtpConfigModalOverlay");
    const mtpCfgEditorOpen = Boolean(mtpCfgOverlay && !mtpCfgOverlay.classList.contains("hidden"));
    if (!mtpCfgEditorOpen) {
      $("mtpConfigText").value = s.config_text || "";
    }

    const cfgOk = Boolean(s.config_exists);
    const mtInstallBtn = document.getElementById("mtpInstallBtn");
    if (mtInstallBtn) {
      mtInstallBtn.textContent = cfgOk ? "Обновить MTProto" : "Установить MTProto";
      mtInstallBtn.dataset.action = cfgOk ? "update" : "install";
    }
    setMtprotoPanelLocked(!cfgOk);
    const up = s.upstream || {};
    const ob = $("mtpOutboundMode");
    if (ob) {
      const m = up.mode === "egress" ? "egress" : up.mode === "tunnel" ? "tunnel" : "direct";
      ob.value = m;
      ob.disabled = !cfgOk;
    }
    const om = $("mtpOutboundMeta");
    if (om) {
      const parts = [];
      if (up.public_ip_derived) parts.push(`public_ip → ${up.public_ip_derived}`);
      if (up.middle_proxy_nat_ip_derived) parts.push(`middle_proxy_nat_ip → ${up.middle_proxy_nat_ip_derived}`);
      parts.push(`egress ${up.egress_dev || "—"} · ingress ${up.ingress_dev || "—"}`);
      const cfgIf = String(up.tunnel_interface_config || "").trim();
      if (cfgIf) parts.push(`[upstream.tunnel] ${cfgIf}`);
      if (up.tunnel_iface_up === false) parts.push("туннель awg-uplink не UP");
      om.textContent = parts.join(" · ");
    }

    const users = s.users || [];
    const pending = state.mtprotoPendingToggles || {};
    reconcileMtprotoPendingToggles(users, pending);
    renderMtprotoUsers(users, pending);
    const usersCount = Number(s.users_total ?? users.length);
    const sessionsOpen = Number(s.sessions_total ?? users.reduce((acc, u) => acc + Number(u.sessions || 0), 0));
    const sessionsCap = Number(s.sessions_cap ?? usersCount * 9);
    const unassigned = Number(s.unassigned ?? Math.max(0, sessionsCap - sessionsOpen));
    $("mtpUsersMeta").textContent = `${usersCount} users · sessions ${sessionsOpen}/${sessionsCap} · unassigned ${unassigned}`;

    const svcOk = Boolean((s.service || {}).ok);
    const n = users.length;
    if (!cfgOk) {
      setStatusById("mtprotoUsersStatus", "dot--warn", "MTProto не настроен (нет config.toml)");
    } else if (!svcOk) {
      setStatusById("mtprotoUsersStatus", "dot--warn", "конфиг есть, прокси не активен");
    } else if (n === 0) {
      setStatusById("mtprotoUsersStatus", "dot--muted", "в конфиге нет пользователей");
    } else {
      setStatusById("mtprotoUsersStatus", "dot--ok", `загружено — ${ruUsersCount(n)}`);
    }

    setStatusById("mtpConfigStatus", s.config_exists ? "dot--ok" : "dot--warn", s.config_exists ? "загружен" : "не найден");
    const svc = s.service || {};
    const svcName = svc.name || "mtproto-proxy";
    const svcState = svc.state || "unknown";
    setStatusById(
      "mtprotoServiceStatus",
      svcOk ? "dot--ok" : "dot--bad",
      `health: ${svcName} ${svcState}`
    );

    const mh = s.masking_health || {};
    const ok = Boolean(mh.ok);
    const enabled = mh.enabled !== false;
    const mode = mh.mode || "local";
    const maskStatusRoot = document.getElementById("mtpMaskStatus");
    if (!enabled) {
      setStatusById("mtpMaskStatus", "dot--warn", "Выключено");
      if (maskStatusRoot) maskStatusRoot.title = "";
    } else if (ok) {
      if (mode === "remote") {
        setStatusById("mtpMaskStatus", "dot--ok", "Удалённый режим");
      } else {
        setStatusById("mtpMaskStatus", "dot--ok", "Норма");
      }
      if (maskStatusRoot) maskStatusRoot.title = "";
    } else {
      const detail = maskingIssueSummaryText(mh);
      const headline = mode === "remote" ? "Удалённый режим — " : "";
      setStatusById("mtpMaskStatus", "dot--warn", `${headline}${detail}`);
      if (maskStatusRoot) maskStatusRoot.title = detail;
    }

    if (!enabled) {
      setHealthRowStatus("mtpMaskModeStatus", "dot--warn", "выключено");
    } else if (mode === "remote") {
      setHealthRowStatus("mtpMaskModeStatus", "dot--ok", "удалённый");
    } else {
      setHealthRowStatus("mtpMaskModeStatus", "dot--ok", "локальный");
    }

    const endpoint = mh.endpoint || `127.0.0.1:${String(s.censorship?.mask_port ?? "--")}`;
    const endpointStateRaw = mh.endpoint_status || (mh.endpoint_ok ? "OK" : "DOWN");
    const epUp = String(endpointStateRaw).toUpperCase() === "OK" || mh.endpoint_ok === true;
    if (!enabled) {
      setHealthRowStatus("mtpMaskEndpointStatus", "dot--warn", "не используется");
    } else if (epUp) {
      setHealthRowStatus("mtpMaskEndpointStatus", "dot--ok", `${endpoint} (доступна)`);
    } else {
      setHealthRowStatus("mtpMaskEndpointStatus", "dot--bad", `${endpoint} (недоступна)`);
    }

    const nginx = mh.nginx || {};
    const na = String(nginx.active || "").toLowerCase();
    let ngxDot = "dot--unknown";
    if (na === "active") ngxDot = "dot--ok";
    else if (na === "inactive" || na === "failed") ngxDot = "dot--bad";
    else if (na) ngxDot = "dot--warn";
    const nginxText = `${systemdStateRu(nginx.active)} / ${systemdStateRu(nginx.enabled)}`;
    setHealthRowStatus("mtpMaskNginxStatus", ngxDot, nginxText);

    const timer = mh.health_timer || {};
    const ta = String(timer.active || "").toLowerCase();
    let timerDot = "dot--unknown";
    if (ta === "active") timerDot = "dot--ok";
    else if (ta === "inactive" || ta === "failed") timerDot = "dot--bad";
    else if (ta) timerDot = "dot--warn";
    const timerText = `${systemdStateRu(timer.active)} / ${systemdStateRu(timer.enabled)}`;
    setHealthRowStatus("mtpMaskTimerStatus", timerDot, timerText);
  } catch {
    setStatusById("mtprotoUsersStatus", "dot--bad", "ошибка загрузки");
    setStatusById("mtprotoServiceStatus", "dot--bad", "health: ошибка");
    setStatusById("mtpMaskStatus", "dot--bad", "ошибка загрузки");
    const upMetaErr = $("mtpOutboundMeta");
    if (upMetaErr) upMetaErr.textContent = "";
    const maskErrRoot = document.getElementById("mtpMaskStatus");
    if (maskErrRoot) maskErrRoot.title = "";
    setHealthRowStatus("mtpMaskModeStatus", "dot--bad", "ошибка загрузки");
    setHealthRowStatus("mtpMaskEndpointStatus", "dot--bad", "ошибка загрузки");
    setHealthRowStatus("mtpMaskNginxStatus", "dot--bad", "ошибка загрузки");
    setHealthRowStatus("mtpMaskTimerStatus", "dot--bad", "ошибка загрузки");
    setStatusById("mtpConfigStatus", "dot--bad", "ошибка загрузки");
  }
}

function findMtprotoUserInState(mtprotoState, username) {
  const list = (mtprotoState && mtprotoState.users) || [];
  return list.find((x) => String(x.username || "") === String(username));
}

/**
 * Server returns quickly and restarts MTProto in the background (same :443 would drop an in-flight request).
 * Poll /api/mtproto/state until the unit is healthy and optional predicate matches (config on disk).
 */
async function waitMtprotoHealthyAfterMutation(state, predicate, opts = {}) {
  const minWaitMs = opts.minWaitMs ?? 400;
  const timeoutMs = opts.timeoutMs ?? 90000;
  const pollMs = opts.pollMs ?? 300;
  const stableOkRounds = opts.stableOkRounds ?? 2;

  await sleepMs(minWaitMs);
  let streak = 0;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await refreshMtprotoState(state);
    const m = state.mtproto;
    const svcOk = Boolean(m && m.service && m.service.ok);
    const predOk = !predicate || predicate(m);
    if (svcOk && predOk) {
      streak++;
      if (streak >= stableOkRounds) return;
    } else {
      streak = 0;
    }
    await sleepMs(pollMs);
  }
  throw new Error("MTProto не поднялся после перезапуска или состояние не совпало с ожиданием");
}

function normalizeMtprotoConfigText(s) {
  return String(s || "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
}

async function waitMtprotoHealthyAfterConfigSave(state, appliedText) {
  const want = normalizeMtprotoConfigText(appliedText);
  await waitMtprotoHealthyAfterMutation(
    state,
    (m) => normalizeMtprotoConfigText(m && m.config_text) === want,
    {}
  );
}

async function waitMtprotoHealthyAfterUserMutation(state, spec) {
  const kind = spec.kind;
  if (kind === "upsert") {
    const un = spec.username;
    const sec = String(spec.secret || "");
    await waitMtprotoHealthyAfterMutation(
      state,
      (m) => {
        const u = findMtprotoUserInState(m, un);
        return Boolean(u && u.enabled !== false && String(u.secret || "").toLowerCase() === sec.toLowerCase());
      },
      {}
    );
    return;
  }
  if (kind === "delete") {
    const un = spec.username;
    await waitMtprotoHealthyAfterMutation(state, (m) => !findMtprotoUserInState(m, un), {});
    return;
  }
  if (kind === "toggle") {
    const un = spec.username;
    const want = Boolean(spec.enabled);
    await waitMtprotoHealthyAfterMutation(
      state,
      (m) => {
        const u = findMtprotoUserInState(m, un);
        if (!u) return false;
        return Boolean(u.enabled) === want;
      },
      {}
    );
    return;
  }
  throw new Error("waitMtprotoHealthyAfterUserMutation: unknown kind");
}

function dnsCfgBool(v, defaultVal = false) {
  if (v === true) return true;
  if (v === false) return false;
  if (v === "true" || v === 1) return true;
  if (v === "false" || v === 0 || v === "") return false;
  return defaultVal;
}

function markDnsPanelDirty() {
  window.__dnsPanelDirty = true;
}

function clearDnsPanelDirty() {
  window.__dnsPanelDirty = false;
}

async function refreshDnsPanel() {
  try {
    const data = await fetchJson("/api/dns/config");
    if (!data || !data.config) return;
    const c = data.config;
    const dirty = Boolean(window.__dnsPanelDirty);
    if (!dirty) {
      $("dnsUpstreamTa").value = Array.isArray(c.upstream_servers) ? c.upstream_servers.join("\n") : "";
      $("dnsDnscryptTa").value = Array.isArray(c.dnscrypt_server_names) ? c.dnscrypt_server_names.join("\n") : "";
    }

    const dmOk = Boolean(data.dnsmasq_active);
    const dcOk = Boolean(data.dnscrypt_active);
    setHealthRowStatus("dnsHealthDnsmasqStatus", dmOk ? "dot--ok" : "dot--bad", dmOk ? "активен" : "не активен");
    setHealthRowStatus("dnsHealthDnscryptStatus", dcOk ? "dot--ok" : "dot--bad", dcOk ? "активен" : "не активен");

    const tl = data.dns_transport_lock || {};
    const tlOn = dnsCfgBool(c.dns_transport_lock_enabled);
    const tlToggle = $("dnsTransportLockToggle");
    if (!dirty && tlToggle) tlToggle.checked = tlOn;
    const tlActive = Boolean(tl.nft_active);
    let tlWarn = false;
    let tlDot = "dot--ok";
    let tlText = "—";
    if (!tlOn) {
      if (tlActive) {
        tlWarn = true;
        tlDot = "dot--warn";
        tlText =
          "в конфиге разблокировано, nft ещё есть — проверьте awg-uplink-dns-transport-lock.service";
      } else {
        tlDot = "dot--muted";
        tlText = "разблокировано";
      }
    } else if (tlActive) {
      tlDot = "dot--ok";
      tlText = "заблокировано";
    } else {
      tlWarn = true;
      tlDot = "dot--warn";
      tlText = "включено, nft не применён (journalctl -u awg-uplink-dns-transport-lock)";
    }
    setHealthRowStatus("dnsHealthDotStatus", tlDot, tlText);

    const w = data.amnezia_dns_watch || {};
    const present = w.container_present === undefined ? true : Boolean(w.container_present);
    const domainReq = Boolean(w.domain_routing_requires);
    const locked = w.toggle_locked === undefined ? false : Boolean(w.toggle_locked);
    const checked =
      w.toggle_checked === undefined ? dnsCfgBool(c.amnezia_dns_watch_enabled, true) : Boolean(w.toggle_checked);
    const toggleEl = $("dnsAmneziaWatchToggle");
    toggleEl.disabled = locked;
    if (!dirty || locked) toggleEl.checked = checked;

    const missingMsg = AMNEZIA_DNS_MISSING_MSG;
    const detail = String(w.detail || "").trim();

    let amDot = "dot--unknown";
    let amText = "ожидание";
    if (!present) {
      amDot = "dot--bad";
      amText = detail || missingMsg;
    } else if (!w.service_active) {
      amDot = "dot--bad";
      amText = "сервис контроля не активен";
    } else if (!dnsCfgBool(c.amnezia_dns_watch_enabled, true) && !domainReq) {
      amDot = "dot--warn";
      amText = "подмена выкл";
    } else {
      const st = w.status || "";
      const gw = w.forward_ip ? ` → ${w.forward_ip}` : "";
      if (st === "ok") {
        amDot = "dot--ok";
        amText = domainReq ? `подмена ок${gw} (обязательно для доменов)` : `подмена ок${gw}`;
      } else if (st === "disabled") {
        amDot = "dot--warn";
        amText = "подмена выкл";
      } else if (st === "no_container") {
        amDot = "dot--bad";
        amText = detail || missingMsg;
      } else if (st === "error") {
        amDot = "dot--bad";
        amText = detail ? `ошибка: ${detail}` : "ошибка подмены";
      } else {
        amDot = "dot--warn";
        amText = String(st || "ожидание");
      }
    }
    setHealthRowStatus("dnsHealthAmneziaStatus", amDot, amText);
    const amRoot = document.getElementById("dnsHealthAmneziaStatus");
    if (amRoot) amRoot.title = detail || (!present ? missingMsg : "");
    window.__amneziaDnsContainerPresent = present;

    let overallKind = "dot--ok";
    let overallText = "Норма";
    let sev = 0;
    if (!dmOk && !dcOk) sev = 2;
    else if (!dmOk || !dcOk) sev = 1;
    if (amDot === "dot--bad") sev = Math.max(sev, 2);
    else if (amDot === "dot--warn") sev = Math.max(sev, 1);
    if (tlWarn) sev = Math.max(sev, 1);
    if (sev >= 2) {
      overallKind = "dot--bad";
      if (!dmOk && !dcOk) overallText = "dnsmasq и dnscrypt-proxy не активны";
      else if (amDot === "dot--bad") overallText = "Проблема Amnezia DNS";
      else overallText = "Ошибка";
    } else if (sev === 1) {
      overallKind = "dot--warn";
      overallText = "Есть замечания";
    }
    setStatusById("dnsHealthOverallStatus", overallKind, overallText);

    const ts = data.domains_list_updated_at;
    $("dnsLastUpdated").textContent = ts
      ? `Списки доменов: ${fmtUnixLocal(ts)}`
      : "Списки доменов: не обновлялись";
  } catch {
    setStatusById("dnsHealthOverallStatus", "dot--bad", "ошибка загрузки");
    setHealthRowStatus("dnsHealthDnsmasqStatus", "dot--unknown", "—");
    setHealthRowStatus("dnsHealthDnscryptStatus", "dot--unknown", "—");
    setHealthRowStatus("dnsHealthAmneziaStatus", "dot--unknown", "—");
    setHealthRowStatus("dnsHealthDotStatus", "dot--unknown", "—");
    const amRoot = document.getElementById("dnsHealthAmneziaStatus");
    if (amRoot) amRoot.title = "";
  }
}

function initDnsPanel() {
  for (const id of ["dnsUpstreamTa", "dnsDnscryptTa"]) {
    $(id).addEventListener("input", () => markDnsPanelDirty());
  }
  $("dnsTransportLockToggle").addEventListener("change", () => markDnsPanelDirty());
  $("dnsAmneziaWatchToggle").addEventListener("change", () => markDnsPanelDirty());

  $("dnsApplyBtn").addEventListener("click", async () => {
    const btn = $("dnsApplyBtn");
    try {
      btn.disabled = true;
      const payload = {
        upstream_servers: $("dnsUpstreamTa").value,
        dnscrypt_server_names: $("dnsDnscryptTa").value,
        amnezia_dns_watch_enabled: $("dnsAmneziaWatchToggle").checked,
        dns_transport_lock_enabled: $("dnsTransportLockToggle").checked,
      };
      const res = await withBusyOverlay("Применяем настройки DNS…", async () => {
        return await postJsonAwaitTask("/api/dns/save", payload);
      });
      clearDnsPanelDirty();
      await refreshDnsPanel();
      const wr = res && res.amnezia_dns_watch;
      if (wr && wr.container_present === false && wr.domain_routing_requires) {
        toast(wr.detail || AMNEZIA_DNS_MISSING_MSG, "warn", 7000);
      }
      toast("DNS применён.", "ok", 2600);
    } catch (e) {
      toast(`Ошибка применения DNS: ${e?.message || "unknown"}`, "error", 3200);
    } finally {
      btn.disabled = false;
    }
  });
}

function initMtprotoPanel(state) {
  const mtInstallBtn = $("mtpInstallBtn");
  let pendingMtprotoAction = "install";
  const mtpDeleteOverlay = $("mtpDeleteUserConfirmOverlay");
  const mtpDeleteText = $("mtpDeleteUserConfirmText");
  let resolveDeleteConfirm = null;
  const mtpWarnOverlay = $("mtpInstallWarnOverlay");
  const pendingToggles = (state.mtprotoPendingToggles = state.mtprotoPendingToggles || {});
  const closeMtpWarn = () => {
    mtpWarnOverlay.classList.add("hidden");
    mtpWarnOverlay.setAttribute("aria-hidden", "true");
  };
  const openMtpWarn = () => {
    mtpWarnOverlay.classList.remove("hidden");
    mtpWarnOverlay.setAttribute("aria-hidden", "false");
    $("mtpInstallWarnContinueBtn").focus();
  };
  $("mtpInstallWarnCloseBtn").addEventListener("click", closeMtpWarn);
  $("mtpInstallWarnCancelBtn").addEventListener("click", closeMtpWarn);
  mtpWarnOverlay.addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "mtpInstallWarnOverlay") closeMtpWarn();
  });

  const closeDeleteConfirm = (confirmed) => {
    mtpDeleteOverlay.classList.add("hidden");
    mtpDeleteOverlay.setAttribute("aria-hidden", "true");
    const cb = resolveDeleteConfirm;
    resolveDeleteConfirm = null;
    if (typeof cb === "function") cb(Boolean(confirmed));
  };
  const openDeleteConfirm = (username) =>
    new Promise((resolve) => {
      resolveDeleteConfirm = resolve;
      mtpDeleteText.textContent = `Вы действительно хотите удалить пользователя "${username}"? Это действие необратимо.`;
      mtpDeleteOverlay.classList.remove("hidden");
      mtpDeleteOverlay.setAttribute("aria-hidden", "false");
      $("mtpDeleteUserConfirmOkBtn").focus();
    });
  $("mtpDeleteUserConfirmCloseBtn").addEventListener("click", () => closeDeleteConfirm(false));
  $("mtpDeleteUserConfirmCancelBtn").addEventListener("click", () => closeDeleteConfirm(false));
  $("mtpDeleteUserConfirmOkBtn").addEventListener("click", () => closeDeleteConfirm(true));
  mtpDeleteOverlay.addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "mtpDeleteUserConfirmOverlay") closeDeleteConfirm(false);
  });

  async function runMtprotoInstallAction(action) {
    const title = action === "update" ? "Обновляем MTProto…" : "Устанавливаем MTProto…";
    try {
      mtInstallBtn.disabled = true;
      const res = await withBusyOverlay(title, async () => {
        await postJson("/api/mtproto/install", { action });
        const startedAt = Date.now();
        while (true) {
          const st = await fetchJson("/api/mtproto/install/status");
          if (!st || st.running !== true) {
            if (st && st.ok === false) {
              throw new Error(st.error || "install failed");
            }
            return st || {};
          }
          if (Date.now() - startedAt > 45 * 60 * 1000) {
            throw new Error("Превышено время ожидания установки MTProto.");
          }
          await sleepMs(2000);
        }
      });
      const ws = res && res.warnings;
      if (Array.isArray(ws) && ws.length) {
        toast(ws.join(" "), "warn", 5200);
      }
      toast(action === "update" ? "MTProto обновлен." : "MTProto установлен.", "ok", 2600);
      await refreshMtprotoState(state);
    } catch (e) {
      toast(`Ошибка установки MTProto: ${e?.message || "unknown"}`, "error", 4200);
      await refreshMtprotoState(state);
    } finally {
      mtInstallBtn.disabled = false;
    }
  }

  $("mtpInstallWarnContinueBtn").addEventListener("click", async () => {
    closeMtpWarn();
    await runMtprotoInstallAction(pendingMtprotoAction);
  });

  mtInstallBtn.addEventListener("click", async () => {
    const action = String(mtInstallBtn.dataset.action || "auto").toLowerCase();
    pendingMtprotoAction = action === "update" ? "update" : "install";
    openMtpWarn();
  });

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

  const outboundSel = $("mtpOutboundMode");
  if (outboundSel) {
    outboundSel.addEventListener("change", async () => {
      const mode = String(outboundSel.value || "direct").trim();
      try {
        const res = await withBusyOverlay("Применяем исходящий интерфейс MTProto…", async () => {
          return await postJson("/api/mtproto/outbound/set", { mode });
        });
        if (!res || !res.ok) {
          toast((res && res.error) || "Не удалось применить исходящий интерфейс или перезапустить сервис.", "error", 4200);
        } else {
          toast("MTProto: config.toml обновлён, сервис перезапущен.", "ok", 2200);
        }
        const ws = res && res.warnings;
        if (ws && ws.length) toast(ws.join(" "), "warn", 5200);
        await refreshMtprotoState(state);
      } catch (e) {
        toast(`Ошибка: ${e?.message || "unknown"}`, "error", 3200);
        await refreshMtprotoState(state);
      }
    });
  }

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
      await withBusyOverlay("Сохраняем пользователя MTProto…", async () => {
        await postJson("/api/mtproto/users/upsert", { username, secret });
        setBusyOverlayText("Дожидаемся перезапуска MTProto…");
        await waitMtprotoHealthyAfterUserMutation(state, { kind: "upsert", username, secret });
      });
      setUserFormStatus("Сохранено.", "ok");
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
      const ok = await openDeleteConfirm(uname);
      if (!ok) return;
      try {
        await withBusyOverlay("Удаляем пользователя MTProto…", async () => {
          await postJson("/api/mtproto/users/delete", { username: uname });
          setBusyOverlayText("Дожидаемся перезапуска MTProto…");
          await waitMtprotoHealthyAfterUserMutation(state, { kind: "delete", username: uname });
        });
        toast("Пользователь удален.", "ok");
      } catch {
        setStatusById("mtprotoUsersStatus", "dot--bad", "ошибка удаления");
        toast("Ошибка удаления пользователя.", "error", 2200);
      }
      return;
    }
    if (toggleUser) {
      const enabledNow = t.getAttribute("data-enabled") === "1";
      const targetEnabled = !enabledNow;
      pendingToggles[toggleUser] = { enabled: targetEnabled };
      if (state.mtproto && Array.isArray(state.mtproto.users)) {
        renderMtprotoUsers(state.mtproto.users, pendingToggles);
      }
      try {
        await withBusyOverlay("Переключаем пользователя MTProto…", async () => {
          await postJson("/api/mtproto/users/toggle", { username: toggleUser, enabled: targetEnabled });
          setBusyOverlayText("Дожидаемся перезапуска MTProto…");
          await waitMtprotoHealthyAfterUserMutation(state, {
            kind: "toggle",
            username: toggleUser,
            enabled: targetEnabled,
          });
        });
        delete pendingToggles[toggleUser];
        await refreshMtprotoState(state);
        toast(enabledNow ? "Пользователь выключен." : "Пользователь включен.", "ok");
      } catch {
        delete pendingToggles[toggleUser];
        await refreshMtprotoState(state);
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
      const res = await withBusyOverlay("Сохраняем config.toml MTProto…", async () => {
        const r = await postJson("/api/mtproto/config/save", { config_text: $("mtpConfigText").value });
        if (r && r.restart_deferred) {
          setBusyOverlayText("Дожидаемся перезапуска MTProto…");
          const applied =
            r && typeof r.config_text_applied === "string" ? r.config_text_applied : null;
          if (applied !== null) {
            await waitMtprotoHealthyAfterConfigSave(state, applied);
          } else {
            await waitMtprotoHealthyAfterMutation(state, null, {});
          }
        }
        return r;
      });
      setStatusById("mtpConfigStatus", "dot--ok", "сохранено");
      $("mtpConfigModalOverlay").classList.add("hidden");
      await refreshMtprotoState(state);
      toast("config.toml сохранен.", "ok");
      const sync = res && res.mtproto_sync;
      if (sync && sync.warnings && sync.warnings.length) toast(sync.warnings.join(" "), "warn", 5200);
      if (sync && !sync.ok && sync.error) toast(sync.error, "error", 3800);
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
    state.interfaceConfigReady = isInterfaceConfigReady(cfg);
    setInterfaceConfigGateLocked(!state.interfaceConfigReady);
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
    const fw = cfg.firewall || {};
    $("ifaceFwEgressPorts").value = Array.isArray(fw.egress_tcp_ports) ? fw.egress_tcp_ports.join(", ") : "";
    $("ifaceFwIngressPorts").value = Array.isArray(fw.ingress_tcp_ports) ? fw.ingress_tcp_ports.join(", ") : "";
    if ($("ifaceFwEnabled")) {
      $("ifaceFwEnabled").checked = fw.enabled !== false;
    }
    if (cfg.route_mode) {
      state.routeMode = cfg.route_mode;
      state.persistedRouteMode = cfg.route_mode;
    }
    if (cfg.geo && typeof cfg.geo === "object") {
      const g = cfg.geo;
      state.geo.target = g.target === "egress" ? "egress" : "tunnel";
      state.geo.ipMode = Boolean(g.ipMode);
      state.geo.domainMode = Boolean(g.domainMode);
      if (g.readyLinks && typeof g.readyLinks === "object") {
        if (Array.isArray(g.readyLinks.ip)) state.geo.readyLinks.ip = g.readyLinks.ip;
        if (Array.isArray(g.readyLinks.domain)) state.geo.readyLinks.domain = g.readyLinks.domain;
      }
      if (g.lists && typeof g.lists === "object") {
        state.geo.lists.ipInclude = String(g.lists.ipInclude || "");
        state.geo.lists.ipExclude = String(g.lists.ipExclude || "");
        state.geo.lists.domainInclude = String(g.lists.domainInclude || "");
        state.geo.lists.domainExclude = String(g.lists.domainExclude || "");
      }
    }
    commitSavedGeoFingerprint(state, state.geo);
    state.ifaceFwSyncDirty = false;
    refreshInterfaceStatuses(saved && saved.runtime ? saved.runtime : null);
  } catch {
    commitSavedGeoFingerprint(state, state.geo);
    state.interfaceConfigReady = false;
    setInterfaceConfigGateLocked(true);
  }
}

function initIfaceFirewallSync(state) {
  const mark = () => {
    state.ifaceFwSyncDirty = true;
  };
  for (const id of ["ifaceFwEnabled", "ifaceFwEgressPorts", "ifaceFwIngressPorts"]) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.addEventListener("change", mark);
    el.addEventListener("input", mark);
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
      geo: window.__awgState && window.__awgState.geo ? window.__awgState.geo : {},
      firewall: {
        enabled: !$("ifaceFwEnabled") || $("ifaceFwEnabled").checked,
        egress_tcp_ports: $("ifaceFwEgressPorts").value,
        ingress_tcp_ports: $("ifaceFwIngressPorts").value,
      },
    };
    if (!body.egress_dev || !body.egress_ip) {
      toast("Нужно выбрать egress интерфейс и IPv4.", "error", 2200);
      return;
    }
    try {
      btn.disabled = true;
      const res = await withBusyOverlay("Применяем маршрутизацию интерфейсов…", async () => {
        return await postJsonAwaitTask("/api/net/routing/save", body);
      });
      refreshInterfaceStatuses(res && res.runtime ? res.runtime : null);
      if (res && res.config && res.config.route_mode && window.__awgState) {
        window.__awgState.routeMode = res.config.route_mode;
        window.__awgState.persistedRouteMode = res.config.route_mode;
      }
      if (res && res.config && res.config.geo && window.__awgState) {
        commitSavedGeoFingerprint(window.__awgState, res.config.geo);
      } else if (window.__awgState) {
        commitSavedGeoFingerprint(window.__awgState, window.__awgState.geo);
      }
      if (window.__awgState) {
        window.__awgState.interfaceConfigReady = isInterfaceConfigReady(res && res.config ? res.config : body);
      }
      setInterfaceConfigGateLocked(!(window.__awgState && window.__awgState.interfaceConfigReady));
      toast("Сохранено успешно. Маршрутизация применена.", "ok");
      if (res && res.warning) toast(String(res.warning), "warn", 5200);
      if (res && res.mtproto_sync_warning) toast(String(res.mtproto_sync_warning), "warn", 5200);
      if (window.__awgState) window.__awgState.ifaceFwSyncDirty = false;
      await refreshDnsPanel();
      if (window.__awgState) await refreshMtprotoState(window.__awgState);
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
      const res = await withBusyOverlay("Применяем netplan… связь может кратко пропасть, маршруты восстановятся автоматически.", async () => {
        await postJson("/api/netplan/validate", { config_text: text.value });
        return await postJsonAwaitTask("/api/netplan/save", { config_text: text.value });
      });
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

/** Сравнение geo без volatile полей (status списков после обновления таймером). */
function normalizeGeoReadyEntry(entry) {
  if (typeof entry === "string") {
    return { url: entry, enabled: true };
  }
  if (!entry || typeof entry !== "object") {
    return { url: "", enabled: true };
  }
  return {
    url: String(entry.url || ""),
    enabled: entry.enabled !== false,
  };
}

/** Строка-снимок «что считается сохранёнными настройками» для сравнения с UI. */
function geoSettingsFingerprint(geo) {
  if (!geo || typeof geo !== "object") return "{}";
  const lists = geo.lists || {};
  const ipRaw = Array.isArray(geo.readyLinks?.ip) ? geo.readyLinks.ip : [];
  const domRaw = Array.isArray(geo.readyLinks?.domain) ? geo.readyLinks.domain : [];
  const ip = ipRaw.map(normalizeGeoReadyEntry).sort((a, b) => a.url.localeCompare(b.url));
  const domain = domRaw.map(normalizeGeoReadyEntry).sort((a, b) => a.url.localeCompare(b.url));
  const payload = {
    target: geo.target === "egress" ? "egress" : "tunnel",
    ipMode: Boolean(geo.ipMode),
    domainMode: Boolean(geo.domainMode),
    lists: {
      ipInclude: String(lists.ipInclude || ""),
      ipExclude: String(lists.ipExclude || ""),
      domainInclude: String(lists.domainInclude || ""),
      domainExclude: String(lists.domainExclude || ""),
    },
    readyLinks: { ip, domain },
  };
  return JSON.stringify(payload);
}

function commitSavedGeoFingerprint(state, geoLike) {
  const src = geoLike && typeof geoLike === "object" ? geoLike : state.geo;
  state.savedGeoFingerprint = geoSettingsFingerprint(src);
}

/** Подтянуть status с сервера (обновляет geo-ip-refresh в georouting.json), не трогая url/enabled. */
function mergeReadyLinkStatusesFromServer(intoGeo, fromGeo) {
  if (!intoGeo || !fromGeo || !fromGeo.readyLinks || typeof fromGeo.readyLinks !== "object") return;
  const pairs = [
    [intoGeo.readyLinks?.ip, fromGeo.readyLinks.ip],
    [intoGeo.readyLinks?.domain, fromGeo.readyLinks.domain],
  ];
  for (const [locArr, remArr] of pairs) {
    if (!Array.isArray(locArr) || !Array.isArray(remArr)) continue;
    for (const loc of locArr) {
      const u = String(loc.url || "");
      if (!u) continue;
      const rem = remArr.find((x) => String(x.url || "") === u);
      if (rem && typeof rem.status === "string") {
        loc.status = rem.status;
      }
    }
  }
}

function initRoutingPanel(state) {
  const root = $("routingModes");
  const geoFieldset = $("geoRoutingFieldset");
  const geoTarget = $("geoRouteTarget");
  const geoIpModeBtn = $("geoIpModeBtn");
  const geoDomainModeBtn = $("geoDomainModeBtn");
  const geoApplyBtn = $("geoApplyBtn");
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

  async function ensureAmneziaDnsWatchEnabledNow() {
    const payload = {
      upstream_servers: $("dnsUpstreamTa").value,
      dnscrypt_server_names: $("dnsDnscryptTa").value,
      amnezia_dns_watch_enabled: true,
      dns_transport_lock_enabled: $("dnsTransportLockToggle").checked,
    };
    await postJsonAwaitTask("/api/dns/save", payload);
    clearDnsPanelDirty();
    await refreshDnsPanel();
  }

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

    if (kind === "domain" && state.geo.domainMode && window.__amneziaDnsContainerPresent === false) {
      setStatusById("geoDomainReadyStatus", "dot--bad", AMNEZIA_DNS_GEO_HINT);
      return;
    }

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
    } else if (!state.geo.ipMode && !state.geo.domainMode) {
      setStatusById("geoRoutingStatus", "dot--warn", "Требуется включить хотя бы один режим");
    } else if (state.persistedRouteMode !== "georouting") {
      setStatusById("geoRoutingStatus", "dot--warn", "не применено");
    } else if (geoSettingsFingerprint(state.geo) !== state.savedGeoFingerprint) {
      setStatusById("geoRoutingStatus", "dot--warn", "не применено: есть несохранённые изменения");
    } else {
      setStatusById("geoRoutingStatus", "dot--ok", "применено");
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
    geoApplyBtn.disabled = !geoSelected;
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
      if (state.persistedRouteMode === "georouting") {
        setStatusById("routingModeStatus", "dot--ok", "georouting: применено");
      } else {
        setStatusById("routingModeStatus", "dot--warn", "georouting: пока не применено");
      }
      refreshGeoUi();
      return;
    }
    setRouteModeStatus(mode, false);
    try {
      const res = await withBusyOverlay("Применяем режим маршрутизации…", async () => {
        return await postJsonAwaitTask("/api/net/routing/mode", { route_mode: mode });
      });
      state.routeMode = (res && res.config && res.config.route_mode) || mode;
      state.persistedRouteMode = state.routeMode;
      if (res && res.config && res.config.geo) {
        commitSavedGeoFingerprint(state, res.config.geo);
      }
      for (const btn of root.querySelectorAll(".routing-mode-btn")) {
        const active = btn.getAttribute("data-route-mode") === state.routeMode;
        btn.classList.toggle("is-active", active);
      }
      setRouteModeStatus(state.routeMode, true);
      if (!options.silent) toast(state.routeMode === "tunnel" ? "Режим туннеля применен." : "Режим egress применен.", "ok");
      refreshGeoUi();
      await refreshDnsPanel();
      if (res && res.mtproto_sync_warning) toast(String(res.mtproto_sync_warning), "warn", 5200);
      await refreshMtprotoState(state);
    } catch (e) {
      setRouteModeStatus(mode, false);
      if (!options.silent) toast(`Ошибка применения режима: ${e?.message || "unknown"}`, "error", 2800);
    }
  };

  async function applyGeoRouting() {
    if (state.routeMode !== "georouting") return;
    const btn = geoApplyBtn;
    try {
      btn.disabled = true;
      // Reuse the same API as interface save to persist geo config + apply base routing + refresh services.
      const body = {
        egress_dev: $("egressDev").value,
        egress_ip: $("egressIp").value,
        egress_gw: $("egressGw").value.trim(),
        ingress_dev: $("ingressDev").value,
        ingress_ip: $("ingressIp").value,
        ingress_gw: $("ingressGw").value.trim(),
        route_mode: "georouting",
        geo: state.geo || {},
        apply_geo_ip_refresh: true,
        firewall: {
          enabled: !$("ifaceFwEnabled") || $("ifaceFwEnabled").checked,
          egress_tcp_ports: $("ifaceFwEgressPorts").value,
          ingress_tcp_ports: $("ifaceFwIngressPorts").value,
        },
      };
      if (!body.egress_dev || !body.egress_ip) {
        toast("Нужно выбрать egress интерфейс и IPv4.", "error", 2200);
        return;
      }
      const res = await withBusyOverlay("Применяем georouting…", async () => {
        return await postJsonAwaitTask("/api/net/routing/save", body);
      });
      state.routeMode = (res && res.config && res.config.route_mode) || "georouting";
      state.persistedRouteMode = state.routeMode;
      for (const b of root.querySelectorAll(".routing-mode-btn")) {
        const active = b.getAttribute("data-route-mode") === state.routeMode;
        b.classList.toggle("is-active", active);
      }
      setStatusById("routingModeStatus", "dot--ok", "georouting: применено");
      if (res && res.config && res.config.geo) {
        commitSavedGeoFingerprint(state, res.config.geo);
      } else {
        commitSavedGeoFingerprint(state, state.geo);
      }
      refreshInterfaceStatuses(res && res.runtime ? res.runtime : null);
      toast("Georouting применен. Сервисы обновления списков перезапущены.", "ok", 2600);
      if (res && res.mtproto_sync_warning) toast(String(res.mtproto_sync_warning), "warn", 5200);
      refreshGeoUi();
      state.ifaceFwSyncDirty = false;
      await refreshDnsPanel();
      await refreshMtprotoState(state);
      try {
        const d = await fetchJson("/api/dns/config");
        const wr = d && d.amnezia_dns_watch;
        if (state.geo && state.geo.domainMode && wr && wr.container_present === false) {
          toast(
            wr.detail || "Отсутствует сервис AmneziaDNS — установите его на сервер из приложения AmneziaVPN.",
            "warn",
            7000,
          );
        }
      } catch {
        /* ignore */
      }
    } catch (e) {
      setStatusById("routingModeStatus", "dot--bad", "georouting: ошибка применения");
      toast(`Ошибка применения georouting: ${e?.message || "unknown"}`, "error", 3200);
      refreshGeoUi();
    } finally {
      btn.disabled = state.routeMode !== "georouting";
    }
  }

  root.addEventListener("click", (ev) => {
    if (!state.tunnelUp) return;
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    const btn = t.closest(".routing-mode-btn");
    if (!(btn instanceof HTMLElement)) return;
    const mode = btn.getAttribute("data-route-mode") || "egress";
    applyMode(mode);
  });

  geoApplyBtn.addEventListener("click", applyGeoRouting);

  geoTarget.addEventListener("change", () => {
    state.geo.target = geoTarget.value || "tunnel";
    refreshGeoUi();
  });
  geoIpModeBtn.addEventListener("click", () => {
    if (state.routeMode !== "georouting") return;
    state.geo.ipMode = !state.geo.ipMode;
    refreshGeoUi();
  });
  geoDomainModeBtn.addEventListener("click", async () => {
    if (state.routeMode !== "georouting") return;
    if (!state.geo.domainMode && window.__amneziaDnsContainerPresent === false) {
      setStatusById("geoDomainReadyStatus", "dot--bad", AMNEZIA_DNS_GEO_HINT);
      toast(AMNEZIA_DNS_MISSING_MSG, "warn", 7000);
      return;
    }
    const enabling = !state.geo.domainMode;
    state.geo.domainMode = enabling;
    refreshGeoUi();
    if (!enabling) return;
    try {
      await ensureAmneziaDnsWatchEnabledNow();
    } catch (e) {
      toast(`Не удалось включить подмену AmneziaDNS: ${e?.message || "unknown"}`, "error", 4200);
    }
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
    toast(
      "Список сохранен локально. Нажмите «Применить», чтобы сохранить изменения на сервере.",
      "ok",
      3200
    );
    refreshGeoUi();
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
    toast(
      "Список добавлен. Нажмите «Применить», чтобы сохранить изменения на сервере.",
      "ok",
      3200
    );
    refreshGeoUi();
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
        refreshGeoUi();
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
      toast(
        "Список удален. Нажмите «Применить», чтобы сохранить изменения на сервере.",
        "ok",
        3200
      );
      refreshGeoUi();
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
    if (state.persistedRouteMode === "georouting") {
      setStatusById("routingModeStatus", "dot--ok", "georouting: применено");
    } else {
      setStatusById("routingModeStatus", "dot--warn", "georouting: пока не применено");
    }
  } else {
    setRouteModeStatus(startMode, true);
  }
  refreshGeoUi();

  async function pollGeoReadyLinkStatuses() {
    if (state.routeMode !== "georouting" && state.persistedRouteMode !== "georouting") return;
    try {
      const saved = await fetchJson("/api/net/routing-config");
      const g = saved && saved.config && saved.config.geo;
      if (!g || typeof g !== "object") return;
      mergeReadyLinkStatusesFromServer(state.geo, g);
      refreshReadyStatus("ip");
      refreshReadyStatus("domain");
      const ek = state.geo.editingReadyKind;
      if (ek && !geoReadyModal.overlay.classList.contains("hidden")) {
        renderReadyModal(ek === "domain" ? "domain" : "ip");
      }
      refreshGeoUi();
    } catch {
      /* transient errors */
    }
  }
  setInterval(pollGeoReadyLinkStatuses, 15000);
  setTimeout(pollGeoReadyLinkStatuses, 2500);
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
    mtprotoPendingToggles: {},
    tunnelUp: false,
    interfaceConfigReady: false,
    ifaceFwSyncDirty: false,
    routeMode: "egress",
    persistedRouteMode: "egress",
    savedGeoFingerprint: "",
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

  applyAppVersionLabels("");
  initImportModal(state);
  initAmneziaSetupBanner();
  initWebUiUpdateBanner();
  initMtprotoPanel(state);
  initDnsPanel();
  initInterfaceSave();
  initNetplanEditor();
  setInterfaceConfigGateLocked(true);

  await initNetworkForm(state);
  initIfaceFirewallSync(state);
  await refreshTunnelStatus(state);
  initRoutingPanel(state);
  await refreshSystemMetrics(state);
  await refreshMtprotoState(state);
  await refreshDnsPanel();
  setInterval(() => refreshTunnelStatus(state), 5000);
  setInterval(() => refreshSystemMetrics(state), 2000);
  setInterval(() => refreshMtprotoState(state), 5000);
  setInterval(() => refreshDnsPanel(), 12000);
}

window.addEventListener("DOMContentLoaded", main);

