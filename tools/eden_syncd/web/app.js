// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const main = $("#main");
const timeZone = (() => {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch { return ""; }
})();

const store = {
  overview: null,
  scopeDetail: null,
  events: null,
  savesQuery: "",
  savesSort: "recent",
  savesFilter: "all",
  activityFilter: "all",
  pruneReport: null,
  verifyReport: null,
};

// ---------- utilities ----------

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

function icon(name) {
  return `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value) || 0;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++; }
  return unit === 0 ? `${size} B` : `${size.toFixed(size >= 100 ? 0 : 1)} ${units[unit]}`;
}

const dateTime = new Intl.DateTimeFormat("zh-CN", {
  year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
});
const shortDate = new Intl.DateTimeFormat("zh-CN", { month: "numeric", day: "numeric" });
const longDay = new Intl.DateTimeFormat("zh-CN", { month: "long", day: "numeric", weekday: "short" });

function validDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) || date.getFullYear() < 2000 ? null : date;
}

function absTime(value) {
  const date = validDate(value);
  return date ? dateTime.format(date) : "—";
}

function relTime(value) {
  const date = validDate(value);
  if (!date) return "从未";
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 45) return "刚刚";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} 天前`;
  return dateTime.format(date).slice(0, 10);
}

function duration(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d} 天 ${h} 小时`;
  if (h) return `${h} 小时 ${m} 分钟`;
  return `${m} 分钟`;
}

function hue(text) {
  let hash = 0;
  for (const c of String(text)) hash = (hash * 31 + c.codePointAt(0)) >>> 0;
  return hash % 360;
}

function shortID(id, size = 10) {
  id = String(id || "");
  return id.length > size + 2 ? `${id.slice(0, size)}…` : id;
}

function storageGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function storageSet(key, value) {
  try { value == null ? localStorage.removeItem(key) : localStorage.setItem(key, value); } catch { /* ignore */ }
}

// ---------- lookup helpers ----------

function scopeByID(id) {
  return store.overview?.scopes.find((s) => s.id === id);
}
function scopeTitle(id) {
  const scope = scopeByID(id);
  return scope?.title || (id ? `存档 ${shortID(id, 8)}` : "未知存档");
}
function deviceByID(id) {
  return store.overview?.devices.find((d) => d.id === id);
}
function deviceName(id) {
  if (!id) return "管理员";
  const device = deviceByID(id);
  return device ? (device.alias || device.name || `设备 ${shortID(id, 6)}`) : `设备 ${shortID(id, 6)}`;
}

function cover(scope, size = "") {
  const title = scope?.title || "";
  const letter = esc((title.trim()[0] || "?").toUpperCase());
  const img = scope?.logo
    ? `<img src="${esc(scope.logo)}" alt="" loading="lazy" referrerpolicy="no-referrer">`
    : "";
  return `<span class="cover ${size}" style="--hue:${hue(scope?.id || title)}">${letter}${img}</span>`;
}

function platformClass(platform) {
  const value = String(platform || "").toLowerCase();
  if (value.includes("win")) return ["windows", "WIN"];
  if (value.includes("android")) return ["android", "AND"];
  if (value.includes("mac") || value.includes("darwin")) return ["macos", "MAC"];
  if (value.includes("ios")) return ["ios", "iOS"];
  if (value.includes("linux") || value.includes("bsd")) return ["linux", "LNX"];
  return ["", value ? esc(value.slice(0, 3).toUpperCase()) : "?"];
}

// ---------- API ----------

class UnauthorizedError extends Error {}

async function api(path, { method = "GET", body, raw = false } = {}) {
  const headers = { "X-Eden-Admin": "1" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`api/${path}`, {
    method, headers, credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) throw new UnauthorizedError();
  if (!response.ok) {
    let message = `请求失败（${response.status}）`;
    try { message = (await response.json()).error || message; } catch { /* ignore */ }
    throw new Error(translateError(message));
  }
  if (raw || response.status === 204) return response;
  return response.json();
}

function translateError(message) {
  const map = {
    "the current snapshot cannot be deleted": "不能删除当前版本",
    "snapshot is already current": "该快照已经是当前版本",
    "too many failed attempts, try again later": "失败次数过多，请稍后再试",
    "invalid administrator token": "管理员令牌不正确",
    "logo must be an http or https URL": "Logo 必须是 http 或 https 地址",
    "verification already running": "完整性校验正在进行中",
    "invalid retention policy": "保留策略无效",
  };
  return map[message] || message;
}

async function guarded(task, success) {
  try {
    const result = await task();
    if (success) toast(success);
    return result;
  } catch (error) {
    if (error instanceof UnauthorizedError) { showLogin(); return undefined; }
    toast(error.message || String(error), true);
    return undefined;
  }
}

async function loadOverview() {
  const query = timeZone ? `?tz=${encodeURIComponent(timeZone)}` : "";
  store.overview = await api(`overview${query}`);
  $("#brand-version").textContent = store.overview.server.version;
  $("#nav-saves").textContent = store.overview.stats.scopes || "";
  $("#nav-devices").textContent = store.overview.stats.devices
    ? `${store.overview.stats.online_devices}/${store.overview.stats.devices}` : "";
}

// ---------- UI primitives ----------

function toast(message, error = false) {
  const element = document.createElement("div");
  element.className = `toast${error ? " error" : ""}`;
  element.textContent = message;
  $("#toasts").append(element);
  setTimeout(() => element.remove(), error ? 5000 : 2800);
}

function modal(html) {
  const root = $("#modal-root");
  root.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${html}</div>`;
  root.hidden = false;
  const close = () => { root.hidden = true; root.innerHTML = ""; };
  root.onclick = (event) => { if (event.target === root) close(); };
  return { root, close };
}

function confirmDialog({ title, message, confirm = "确认", danger = false }) {
  return new Promise((resolve) => {
    const { root, close } = modal(`
      <h2>${esc(title)}</h2><p>${message}</p>
      <div class="modal-actions">
        <button class="btn" type="button" data-answer="no">取消</button>
        <button class="btn ${danger ? "danger solid" : "primary"}" type="button" data-answer="yes">${esc(confirm)}</button>
      </div>`);
    const finish = (value) => { close(); document.removeEventListener("keydown", onKey); resolve(value); };
    const onKey = (event) => { if (event.key === "Escape") finish(false); };
    document.addEventListener("keydown", onKey);
    root.querySelectorAll("[data-answer]").forEach((button) =>
      button.addEventListener("click", () => finish(button.dataset.answer === "yes")));
    root.onclick = (event) => { if (event.target === root) finish(false); };
    root.querySelector('[data-answer="yes"]').focus();
  });
}

function promptDialog({ title, label, value = "", placeholder = "", hint = "" }) {
  return new Promise((resolve) => {
    const { root, close } = modal(`
      <h2>${esc(title)}</h2>
      <form class="form">
        <label class="field"><span>${esc(label)}</span>
          <input type="text" name="value" maxlength="80" value="${esc(value)}" placeholder="${esc(placeholder)}">
          ${hint ? `<small>${esc(hint)}</small>` : ""}
        </label>
        <div class="modal-actions">
          <button class="btn" type="button" data-cancel>取消</button>
          <button class="btn primary" type="submit">保存</button>
        </div>
      </form>`);
    const input = root.querySelector("input");
    const finish = (result) => { close(); resolve(result); };
    root.querySelector("[data-cancel]").onclick = () => finish(null);
    root.querySelector("form").onsubmit = (event) => { event.preventDefault(); finish(input.value.trim()); };
    root.onclick = (event) => { if (event.target === root) finish(null); };
    input.addEventListener("keydown", (event) => { if (event.key === "Escape") finish(null); });
    input.focus();
    input.select();
  });
}

function pageHead(title, subtitle, actions = "") {
  return `<header class="page-head"><div><h1>${esc(title)}</h1>${subtitle ? `<p>${subtitle}</p>` : ""}</div>
    <div class="page-actions">${actions}</div></header>`;
}

function emptyState(title, text) {
  return `<div class="empty"><strong>${esc(title)}</strong>${text}</div>`;
}

// ---------- events ----------

const eventIcons = {
  upload: "download", conflict: "activity", rollback: "restore", delete_snapshot: "trash",
  delete_scope: "trash", prune: "broom", device_new: "devices", device_removed: "devices",
  verify: "shield", settings: "tools",
};

function describeEvent(item) {
  const scope = `<b>${esc(scopeTitle(item.scope))}</b>`;
  const device = `<b>${esc(deviceName(item.device))}</b>`;
  switch (item.kind) {
    case "upload": return [`${device} 上传了 ${scope}`, item.detail];
    case "conflict": return [`${device} 上传 ${scope} 时发生冲突`, "云端已有更新版本，冲突快照保留在该设备本地"];
    case "rollback": return [`${scope} 已恢复到旧版本`, `来源快照 ${shortID((item.detail || "").replace(/^restored /, ""), 16)}`];
    case "delete_snapshot": return [`删除了 ${scope} 的一个快照`, shortID(item.snapshot, 24)];
    case "delete_scope": return [`删除了存档范围 ${item.detail ? `<b>${esc(item.detail)}</b>` : scope}`, ""];
    case "prune": return [item.scope ? `按保留策略清理了 ${scope}` : "执行了存储清理", (item.detail || "").replace("removed", "移除").replace("snapshots", "个快照").replace("objects", "个对象")];
    case "device_new": return [`新设备接入：${device}`, item.detail];
    case "device_removed": return [`移除了设备 <b>${esc(item.detail || shortID(item.device, 8))}</b>`, ""];
    case "verify": return ["完成完整性校验", (item.detail || "").replace(/checked (\d+) objects, (\d+) problems/, "检查 $1 个对象，发现 $2 个问题")];
    case "settings": return ["更新了保留策略", (item.detail || "").replace(/retention: keep (\d+) snapshots, (\d+) days/, "保留 $1 个快照 / $2 天（0 表示不限）")];
    default: return [esc(item.kind), item.detail];
  }
}

function eventRow(item, { withDate = false } = {}) {
  const [text, detail] = describeEvent(item);
  const link = item.scope && scopeByID(item.scope) ? `href="#/saves/${encodeURIComponent(item.scope)}"` : "";
  const tag = link ? "a" : "div";
  return `<${tag} class="row" ${link}>
    <span class="ev ${esc(item.kind)}">${icon(eventIcons[item.kind] || "activity")}</span>
    <span class="grow"><span class="title">${text}</span>${detail ? `<span class="meta">${esc(detail)}</span>` : ""}</span>
    <span class="aside" title="${esc(absTime(item.time))}">${withDate ? esc(absTime(item.time)) : esc(relTime(item.time))}</span>
  </${tag}>`;
}

// ---------- views ----------

function renderOverview() {
  const { stats, server, activity, scopes, events, devices } = store.overview;
  const diskUsed = server.disk_total ? (server.disk_total - server.disk_free) / server.disk_total : 0;
  const saved = Math.max(0, stats.logical_bytes - stats.stored_bytes);
  const meterClass = diskUsed > 0.95 ? "danger" : diskUsed > 0.85 ? "warn" : "";
  const recent = scopes.slice(0, 6);
  const onlineDevices = devices.filter((d) => d.online);

  main.innerHTML = `
    ${pageHead("概览", `存档同步服务运行 ${esc(duration((Date.now() - new Date(server.started_at)) / 1000))}`,
      `<a class="btn" href="#/maintenance">${icon("tools")}维护</a>`)}
    <section class="kpis">
      <div class="card kpi"><span class="label">存档范围</span><span class="value">${stats.scopes}</span>
        <span class="sub">${stats.named_scopes} 个已识别 · ${stats.scopes - stats.named_scopes} 个待命名</span></div>
      <div class="card kpi"><span class="label">快照</span><span class="value">${stats.snapshots}</span>
        <span class="sub">近 7 天上传 ${stats.uploads_7d} 次${stats.pinned_snapshots ? ` · 已固定 ${stats.pinned_snapshots}` : ""}</span></div>
      <div class="card kpi"><span class="label">存储占用</span><span class="value">${formatBytes(stats.stored_bytes)}</span>
        <span class="sub">${stats.objects} 个加密对象${saved ? ` · 去重节省 ${formatBytes(saved)}` : ""}</span></div>
      <div class="card kpi"><span class="label"><span class="dot ${stats.online_devices ? "on" : ""}"></span>在线设备</span>
        <span class="value">${stats.online_devices}<small class="sub"> / ${stats.devices}</small></span>
        <span class="sub">${onlineDevices.length ? esc(onlineDevices.slice(0, 2).map((d) => d.alias || d.name || "未命名").join("、")) : "暂无设备在线"}</span></div>
      ${server.disk_total ? `<div class="card kpi"><span class="label">数据卷</span>
        <span class="value">${formatBytes(server.disk_free)}</span>
        <span class="sub">可用 · 共 ${formatBytes(server.disk_total)}</span>
        <div class="meter ${meterClass}"><i style="width:${(diskUsed * 100).toFixed(1)}%"></i></div></div>` : ""}
    </section>
    <section class="grid two">
      <div class="card">
        <div class="card-head"><h2>近 30 天同步</h2>
          <div class="legend"><span><i style="background:var(--accent)"></i>上传</span><span><i style="background:var(--danger)"></i>冲突</span></div></div>
        <div class="card-body">${activityChart(activity)}</div>
      </div>
      <div class="card">
        <div class="card-head"><h2>最近同步的游戏</h2><a href="#/saves">全部</a></div>
        <div class="card-body list">${recent.length ? recent.map((scope) => `
          <a class="row" href="#/saves/${encodeURIComponent(scope.id)}">${cover(scope, "sm")}
            <span class="grow"><span class="title">${esc(scope.title || "未命名存档")}</span>
              <span class="meta">${esc(deviceName(scope.latest_device))} · ${formatBytes(scope.head_bytes)}</span></span>
            <span class="aside">${esc(relTime(scope.latest_at))}</span></a>`).join("")
          : emptyState("还没有存档", "在 Eden 中启用存档同步并关闭一次游戏后，存档会出现在这里。")}</div>
      </div>
    </section>
    <section class="card section">
      <div class="card-head"><h2>最近活动</h2><a href="#/activity">查看全部</a></div>
      <div class="card-body list">${events.length ? events.slice(0, 8).map((e) => eventRow(e)).join("")
        : emptyState("暂无活动", "上传、冲突、恢复等操作会记录在这里。")}</div>
    </section>`;
}

function activityChart(days) {
  const width = 600, height = 190, top = 12, bottom = 24, left = 26;
  const plotH = height - top - bottom;
  const max = Math.max(4, ...days.map((d) => d.uploads + d.conflicts));
  const step = (width - left) / days.length;
  const barW = Math.max(4, step * 0.62);
  const y = (value) => top + plotH - (value / max) * plotH;
  const ticks = [0, Math.round(max / 2), max];
  let svg = `<svg class="chart" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="近 30 天上传与冲突次数">`;
  for (const tick of ticks) {
    svg += `<line class="grid-line" x1="${left}" x2="${width}" y1="${y(tick)}" y2="${y(tick)}"/>`;
    svg += `<text x="${left - 6}" y="${y(tick) + 3}" text-anchor="end">${tick}</text>`;
  }
  days.forEach((day, index) => {
    const x = left + index * step + (step - barW) / 2;
    const label = `${day.date}：上传 ${day.uploads} 次${day.conflicts ? `，冲突 ${day.conflicts} 次` : ""}`;
    if (day.uploads) {
      svg += `<rect class="bar" x="${x}" y="${y(day.uploads)}" width="${barW}" height="${top + plotH - y(day.uploads)}" rx="2"><title>${esc(label)}</title></rect>`;
    }
    if (day.conflicts) {
      const base = y(day.uploads);
      const h = top + plotH - y(day.conflicts);
      svg += `<rect class="conflict" x="${x}" y="${base - h}" width="${barW}" height="${h}" rx="2"><title>${esc(label)}</title></rect>`;
    }
    if (!day.uploads && !day.conflicts) {
      svg += `<rect fill="transparent" x="${x}" y="${top}" width="${barW}" height="${plotH}"><title>${esc(label)}</title></rect>`;
    }
    if (index % 7 === 0 || index === days.length - 1) {
      const [yy, mm, dd] = day.date.split("-").map(Number);
      svg += `<text x="${x + barW / 2}" y="${height - 6}" text-anchor="middle">${esc(shortDate.format(new Date(yy, mm - 1, dd)))}</text>`;
    }
  });
  return `${svg}</svg>`;
}

function renderSaves() {
  const { scopes } = store.overview;
  const query = store.savesQuery.trim().toLowerCase();
  let items = scopes.filter((scope) => {
    if (store.savesFilter === "unnamed" && scope.named) return false;
    if (store.savesFilter === "pinned" && !scope.pinned_count) return false;
    return !query || scope.id.toLowerCase().includes(query) || (scope.title || "").toLowerCase().includes(query);
  });
  const sorters = {
    recent: (a, b) => new Date(b.latest_at) - new Date(a.latest_at),
    name: (a, b) => (a.title || "￿").localeCompare(b.title || "￿", "zh-CN"),
    size: (a, b) => b.stored_bytes - a.stored_bytes,
    count: (a, b) => b.snapshot_count - a.snapshot_count,
  };
  items = items.slice().sort(sorters[store.savesSort]);
  const unnamed = scopes.filter((s) => !s.named).length;

  main.innerHTML = `
    ${pageHead("存档", `${scopes.length} 个存档范围 · 每个范围对应一个游戏账号存档或设备存档`)}
    <div class="toolbar">
      <label class="search">${icon("search")}<input type="search" id="saves-search" placeholder="搜索游戏名称或范围 ID" value="${esc(store.savesQuery)}"></label>
      <div class="chips">
        <button class="chip ${store.savesFilter === "all" ? "active" : ""}" data-filter="all">全部</button>
        <button class="chip ${store.savesFilter === "unnamed" ? "active" : ""}" data-filter="unnamed">待命名${unnamed ? ` ${unnamed}` : ""}</button>
        <button class="chip ${store.savesFilter === "pinned" ? "active" : ""}" data-filter="pinned">含固定快照</button>
      </div>
      <select id="saves-sort" aria-label="排序">
        <option value="recent">最近同步</option><option value="name">名称</option>
        <option value="size">占用空间</option><option value="count">快照数量</option>
      </select>
    </div>
    <section class="saves" id="saves-grid">${items.length ? items.map(saveCard).join("")
      : `<div class="card" style="grid-column:1/-1">${emptyState(scopes.length ? "没有匹配的存档" : "还没有存档",
        scopes.length ? "尝试其他关键词或筛选条件。" : "在 Eden 中启用存档同步并关闭一次游戏后，存档会出现在这里。")}</div>`}</section>`;

  $("#saves-sort").value = store.savesSort;
  $("#saves-sort").onchange = (event) => { store.savesSort = event.target.value; renderSaves(); };
  const search = $("#saves-search");
  search.oninput = () => {
    store.savesQuery = search.value;
    const position = search.selectionStart;
    renderSaves();
    const next = $("#saves-search");
    next.focus();
    next.setSelectionRange(position, position);
  };
  main.querySelectorAll("[data-filter]").forEach((chip) => {
    chip.onclick = () => { store.savesFilter = chip.dataset.filter; renderSaves(); };
  });
}

function saveCard(scope) {
  return `<a class="card save" href="#/saves/${encodeURIComponent(scope.id)}">
    <div class="save-top">${cover(scope)}
      <div class="save-title"><strong>${esc(scope.title || "未命名存档")}</strong>
        ${scope.named ? "" : `<span class="badge warn">待命名</span>`}
        <code title="${esc(scope.id)}">${esc(scope.id)}</code></div></div>
    <div class="save-stats">
      <div><span>最近同步</span><b title="${esc(absTime(scope.latest_at))}">${esc(relTime(scope.latest_at))}</b></div>
      <div><span>快照</span><b>${scope.snapshot_count}${scope.pinned_count ? ` · ${icon("pin")}${scope.pinned_count}` : ""}</b></div>
      <div><span>占用</span><b>${formatBytes(scope.stored_bytes)}</b></div>
    </div></a>`;
}

async function renderScope(id) {
  if (!store.scopeDetail || store.scopeDetail.scope.id !== id) {
    main.innerHTML = `<div class="skeleton"></div>`;
  }
  const detail = await api(`scopes/${encodeURIComponent(id)}`);
  store.scopeDetail = detail;
  if (currentRoute().id !== id) return;
  const { scope, snapshots } = detail;
  const title = scope.title || "未命名存档";

  main.innerHTML = `
    <a class="back" href="#/saves">${icon("back")}存档</a>
    <section class="card">
      <div class="hero">${cover(scope, "lg")}
        <div class="hero-text">
          <div>${scope.named ? `<span class="badge ok">已识别</span>` : `<span class="badge warn">待命名</span>`}</div>
          <h1>${esc(title)}</h1>
          <div class="hero-id"><code title="${esc(scope.id)}">${esc(scope.id)}</code>
            <button class="icon-btn" data-copy="${esc(scope.id)}" title="复制范围 ID">${icon("copy")}</button></div>
        </div>
      </div>
      <div class="hero-stats">
        <div><span>当前版本</span><b title="${esc(absTime(scope.latest_at))}">${esc(relTime(scope.latest_at))}</b></div>
        <div><span>来自设备</span><b>${esc(deviceName(scope.latest_device))}</b></div>
        <div><span>快照</span><b>${scope.snapshot_count}${scope.pinned_count ? `（固定 ${scope.pinned_count}）` : ""}</b></div>
        <div><span>占用空间</span><b>${formatBytes(scope.stored_bytes)}</b></div>
      </div>
    </section>
    <div class="detail-grid">
      <section class="card">
        <div class="card-head"><h2>快照历史</h2><span class="hint">最新在上 · 当前版本以实心圆标记</span></div>
        <div class="card-body timeline">${snapshots.map((s) => snapshotRow(s)).join("")}</div>
      </section>
      <div class="stack">
        <section class="card">
          <div class="card-head"><h2>显示设置</h2></div>
          <form class="card-body form" id="scope-form">
            <label class="field"><span>显示名称</span>
              <input type="text" name="title" maxlength="120" value="${esc(scope.title)}" placeholder="游戏名称"></label>
            <label class="field"><span>Logo 图片地址</span>
              <input type="url" name="logo_url" maxlength="2048" value="${esc(scope.logo_url)}" placeholder="https://…">
              <small>${scope.has_client_logo ? "当前使用 Eden 客户端上传的游戏图标；填写地址将替换它。" : "可选。Eden 客户端会在下次同步时自动上传游戏图标。"}</small></label>
            ${scope.has_client_logo ? `<label class="check"><input type="checkbox" name="clear_client_logo">移除客户端上传的图标</label>` : ""}
            <button class="btn primary" type="submit">保存</button>
          </form>
        </section>
        <section class="card">
          <div class="card-head"><h2>如何应用恢复的版本</h2></div>
          <div class="card-body"><p class="hint">“设为当前版本”会在云端创建一个指向旧快照的新版本，历史不会丢失。
            设备本地已有存档时不会被自动覆盖：请在该设备的 Eden 中执行 <code>设置 › 网络 › 存档同步 › 下载最新云存档</code>。</p></div>
        </section>
        <section class="card">
          <div class="card-head"><h2>危险操作</h2></div>
          <div class="card-body form">
            <p class="hint">删除整个存档范围会移除其全部快照记录，未被其他存档引用的加密对象将在下次清理时回收。设备本地存档不受影响。</p>
            <button class="btn danger" type="button" data-action="delete-scope">${icon("trash")}删除此存档范围</button>
          </div>
        </section>
      </div>
    </div>`;

  $("#scope-form").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const body = { title: form.get("title"), logo_url: form.get("logo_url") };
    if (form.get("clear_client_logo")) body.clear_client_logo = true;
    const result = await guarded(() => api(`scopes/${encodeURIComponent(id)}`, { method: "PATCH", body }), "已保存显示设置");
    if (result) { await refresh(); }
  };
}

function snapshotRow(item) {
  const badges = [];
  if (item.head) badges.push(`<span class="badge accent">当前版本</span>`);
  if (item.pinned) badges.push(`<span class="badge ok">${icon("pin")}已固定</span>`);
  if (item.restored_of) badges.push(`<span class="badge warn" title="${esc(item.restored_of)}">${icon("restore")}恢复自 ${esc(shortID(item.restored_of, 14))}</span>`);
  if (item.shared_blob) badges.push(`<span class="badge" title="与其他快照共享同一加密对象">去重</span>`);
  return `<div class="snap ${item.head ? "head" : ""}">
    <span class="snap-dot"></span>
    <div class="snap-main">
      <div class="snap-line"><strong title="${esc(absTime(item.created_at))}">${esc(absTime(item.created_at))}</strong>
        <span class="hint">${esc(relTime(item.created_at))}</span>${badges.join("")}</div>
      <div class="snap-meta"><span>${esc(deviceName(item.device))}</span><span>${formatBytes(item.size)}</span>
        <code title="${esc(item.id)}">${esc(shortID(item.id, 22))}</code>
        ${item.parent_missing ? `<span title="父版本已被清理">父版本已清理</span>` : ""}</div>
    </div>
    <div class="snap-actions">
      ${item.head ? "" : `<button class="icon-btn" data-action="rollback" data-id="${esc(item.id)}" title="设为当前版本">${icon("restore")}</button>`}
      <button class="icon-btn" data-action="pin" data-id="${esc(item.id)}" data-pinned="${item.pinned ? 1 : 0}" title="${item.pinned ? "取消固定" : "固定（不会被保留策略清理）"}">${icon("pin")}</button>
      <a class="icon-btn" href="api/scopes/${encodeURIComponent(store.scopeDetail.scope.id)}/snapshots/${encodeURIComponent(item.id)}/download" title="下载加密快照" download>${icon("download")}</a>
      ${item.head ? "" : `<button class="icon-btn danger" data-action="delete-snapshot" data-id="${esc(item.id)}" title="删除快照">${icon("trash")}</button>`}
    </div>
  </div>`;
}

function renderDevices() {
  const { devices, server } = store.overview;
  main.innerHTML = `
    ${pageHead("设备", `${devices.length} 台设备 · ${server.online_window_seconds} 秒内有通信视为在线`)}
    ${devices.length ? `<section class="devices">${devices.map(deviceCard).join("")}</section>`
      : `<div class="card">${emptyState("尚未发现设备", "Eden 客户端连接同步服务后会自动出现在这里。")}</div>`}`;
}

function deviceCard(device) {
  const [platformCls, platformLabel] = platformClass(device.platform);
  const display = device.alias || device.name || "未命名设备";
  return `<article class="card device">
    <div class="device-top">
      <span class="platform ${platformCls}">${platformLabel}</span>
      <div class="device-name"><strong><span>${esc(display)}</span>
        ${device.online ? `<span class="badge ok"><span class="dot on"></span>在线</span>` : `<span class="badge">离线</span>`}</strong>
        <small>${device.alias && device.name ? `${esc(device.name)} · ` : ""}${esc(device.platform || "未知平台")}</small></div>
    </div>
    <dl class="kv">
      <dt>最后活动</dt><dd title="${esc(absTime(device.last_seen))}">${esc(relTime(device.last_seen))}</dd>
      <dt>上传快照</dt><dd>${device.uploads} 个${device.last_upload_at ? ` · ${esc(relTime(device.last_upload_at))}` : ""}</dd>
      <dt>Eden 版本</dt><dd>${esc(device.version || "—")}</dd>
      <dt>网络地址</dt><dd class="mono">${esc(device.address || "—")}</dd>
      <dt>首次接入</dt><dd>${esc(absTime(device.first_seen))}</dd>
      <dt>设备 ID</dt><dd class="mono" title="${esc(device.id)}">${esc(shortID(device.id, 18))}</dd>
    </dl>
    <div class="device-foot">
      <button class="btn sm ghost" data-action="rename-device" data-id="${esc(device.id)}">${icon("edit")}重命名</button>
      <button class="btn sm ghost danger" data-action="delete-device" data-id="${esc(device.id)}">${icon("trash")}移除</button>
    </div>
  </article>`;
}

const activityKinds = [
  ["all", "全部"], ["upload", "上传"], ["conflict", "冲突"], ["rollback", "恢复"],
  ["maintenance", "维护"], ["device", "设备"],
];

function matchesActivity(item) {
  switch (store.activityFilter) {
    case "all": return true;
    case "maintenance": return ["prune", "verify", "settings", "delete_snapshot", "delete_scope"].includes(item.kind);
    case "device": return item.kind.startsWith("device");
    default: return item.kind === store.activityFilter;
  }
}

async function renderActivity() {
  if (!store.events) main.innerHTML = `<div class="skeleton"></div>`;
  store.events = (await api("events")).events;
  if (currentRoute().name !== "activity") return;
  const items = store.events.filter(matchesActivity);
  let body = "";
  let lastDay = "";
  for (const item of items) {
    const day = longDay.format(new Date(item.time));
    if (day !== lastDay) { body += `<div class="day-head">${esc(day)}</div>`; lastDay = day; }
    body += eventRow(item);
  }
  main.innerHTML = `
    ${pageHead("活动", "最近 500 条同步与管理事件")}
    <div class="toolbar"><div class="chips">${activityKinds.map(([key, label]) =>
      `<button class="chip ${store.activityFilter === key ? "active" : ""}" data-kind="${key}">${label}</button>`).join("")}</div></div>
    <section class="card"><div class="card-body list">${body || emptyState("没有活动", "当前筛选条件下没有记录。")}</div></section>`;
  main.querySelectorAll("[data-kind]").forEach((chip) => {
    chip.onclick = () => { store.activityFilter = chip.dataset.kind; renderActivity(); };
  });
}

function renderMaintenance() {
  const { settings, server } = store.overview;
  const retention = settings.retention;
  const prune = store.pruneReport;
  const verify = store.verifyReport;
  const origin = location.origin;

  main.innerHTML = `
    ${pageHead("维护", "保留策略、存储清理与完整性校验")}
    <div class="grid two">
      <div class="stack">
        <section class="card">
          <div class="card-head"><h2>快照保留策略</h2>${retention.keep_snapshots || retention.keep_days
            ? `<span class="badge accent">已启用</span>` : `<span class="badge">保留全部</span>`}</div>
          <form class="card-body form" id="retention-form">
            <div class="inline-fields">
              <label class="field"><span>每个存档至少保留最近</span>
                <input type="number" name="keep_snapshots" min="0" max="10000" value="${retention.keep_snapshots}"><small>个快照，0 表示不限</small></label>
              <label class="field"><span>并保留最近</span>
                <input type="number" name="keep_days" min="0" max="36500" value="${retention.keep_days}"><small>天内的快照，0 表示不限</small></label>
            </div>
            <p class="hint">满足任一条件的快照都会保留；当前版本与已固定的快照永远不会被清理。两项都为 0 时不自动清理。
              策略在每次上传后以及每隔一段时间自动执行。</p>
            <div><button class="btn primary" type="submit">保存策略</button></div>
          </form>
        </section>
        <section class="card">
          <div class="card-head"><h2>存储清理</h2></div>
          <div class="card-body">
            <p class="hint">按保留策略移除过期快照，并回收不再被任何快照引用的加密对象（1 小时内上传的对象会跳过）。</p>
            <div class="page-actions" style="margin-top:12px">
              <button class="btn" data-action="prune-preview">${icon("search")}预览</button>
              <button class="btn primary" data-action="prune-run">${icon("broom")}立即清理</button>
            </div>
            ${prune ? `<div class="report ${prune.snapshots || prune.objects ? "" : "ok"}">
              <b>${prune.dry_run ? "预览结果" : "清理完成"}</b>
              <span>${prune.dry_run ? "将移除" : "已移除"} ${prune.snapshots} 个快照（${prune.scopes.length} 个存档范围）、${prune.objects} 个对象，
                ${prune.dry_run ? "可回收" : "回收"} ${formatBytes(prune.reclaimed_bytes)}${prune.temporary_removed ? `，临时文件 ${prune.temporary_removed} 个` : ""}。</span></div>` : ""}
          </div>
        </section>
        <section class="card">
          <div class="card-head"><h2>完整性校验</h2></div>
          <div class="card-body">
            <p class="hint">重新计算每个被引用加密对象的 SHA-256，发现丢失或损坏的快照。数据较多时可能需要几分钟。</p>
            <div class="page-actions" style="margin-top:12px">
              <button class="btn" data-action="verify">${icon("shield")}开始校验</button></div>
            ${verify ? `<div class="report ${verify.problems.length ? "bad" : "ok"}">
              <b>${verify.problems.length ? `发现 ${verify.problems.length} 个问题` : "全部正常"}</b>
              <span>检查 ${verify.objects} 个对象，共 ${formatBytes(verify.bytes)}，用时 ${verify.duration_seconds.toFixed(1)} 秒。</span>
              ${verify.problems.map((p) => `<span>${p.problem === "missing" ? "丢失" : p.problem === "corrupt" ? "损坏" : "无法读取"}：
                ${p.scopes.map((id) => `<a href="#/saves/${encodeURIComponent(id)}"><b>${esc(scopeTitle(id))}</b></a>`).join("、")}
                <code>${esc(shortID(p.blob, 16))}</code></span>`).join("")}
            </div>` : ""}
          </div>
        </section>
      </div>
      <div class="stack">
        <section class="card">
          <div class="card-head"><h2>服务信息</h2></div>
          <div class="card-body"><dl class="kv">
            <dt>版本</dt><dd class="mono">${esc(server.version)}</dd>
            <dt>运行环境</dt><dd class="mono">${esc(server.go_version)}</dd>
            <dt>启动时间</dt><dd>${esc(absTime(server.started_at))}</dd>
            <dt>已运行</dt><dd>${esc(duration((Date.now() - new Date(server.started_at)) / 1000))}</dd>
            <dt>单个对象上限</dt><dd>${formatBytes(server.max_object_bytes)}</dd>
            <dt>请求数</dt><dd>${server.requests.toLocaleString("zh-CN")}</dd>
            ${server.disk_total ? `<dt>数据卷</dt><dd>${formatBytes(server.disk_free)} 可用 / ${formatBytes(server.disk_total)}</dd>` : ""}
          </dl></div>
        </section>
        <section class="card">
          <div class="card-head"><h2>监控与脚本</h2></div>
          <div class="card-body form">
            <p class="hint">Prometheus 指标位于 <code>/metrics</code>，使用 HTTP Basic Auth（任意用户名，密码为管理员令牌）。</p>
            <pre class="snippet">curl -u admin:$EDEN_SYNCD_ADMIN_TOKEN \\
  ${esc(origin)}/metrics</pre>
            <p class="hint">管理 API 位于 <code>/admin/api/</code>，同样支持 Basic Auth；修改类请求需附带请求头 <code>X-Eden-Admin: 1</code>。</p>
          </div>
        </section>
      </div>
    </div>`;

  $("#retention-form").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const body = { retention: {
      keep_snapshots: Number(form.get("keep_snapshots")) || 0,
      keep_days: Number(form.get("keep_days")) || 0,
    } };
    const result = await guarded(() => api("settings", { method: "PUT", body }), "保留策略已保存");
    if (result) { store.pruneReport = null; await refresh(); }
  };
}

// ---------- routing ----------

function currentRoute() {
  const hash = location.hash.replace(/^#\/?/, "");
  const [name, id] = hash.split("/");
  if (name === "saves" && id) return { name: "scope", id: decodeURIComponent(id), nav: "saves" };
  const known = ["saves", "devices", "activity", "maintenance"];
  return { name: known.includes(name) ? name : "overview", nav: known.includes(name) ? name : "overview" };
}

async function render() {
  const route = currentRoute();
  document.querySelectorAll("#nav a").forEach((link) =>
    link.classList.toggle("active", link.dataset.route === route.nav));
  const titles = { overview: "概览", saves: "存档", scope: "存档", devices: "设备", activity: "活动", maintenance: "维护" };
  document.title = `${titles[route.name]} · Eden 存档同步`;
  switch (route.name) {
    case "saves": return renderSaves();
    case "scope": return renderScope(route.id);
    case "devices": return renderDevices();
    case "activity": return renderActivity();
    case "maintenance": return renderMaintenance();
    default: return renderOverview();
  }
}

let refreshing = false;
async function refresh({ quiet = false } = {}) {
  if (refreshing) return;
  refreshing = true;
  try {
    await loadOverview();
    const route = currentRoute();
    // Avoid wiping half-typed form input during background refreshes.
    const editing = main.contains(document.activeElement) && document.activeElement.matches("input, select, textarea");
    if (!(quiet && editing && route.name !== "overview")) await render();
  } catch (error) {
    if (error instanceof UnauthorizedError) showLogin();
    else if (!quiet) toast(error.message || String(error), true);
  } finally {
    refreshing = false;
  }
}

// ---------- actions ----------

async function onAction(event) {
  const target = event.target.closest("[data-action], [data-copy]");
  if (!target) return;
  if (target.dataset.copy) {
    try { await navigator.clipboard.writeText(target.dataset.copy); toast("已复制"); } catch { toast("复制失败", true); }
    return;
  }
  const action = target.dataset.action;
  const id = target.dataset.id;
  const scopeID = store.scopeDetail?.scope.id;
  switch (action) {
    case "theme": return toggleTheme();
    case "refresh": return refresh().then(() => toast("已刷新"));
    case "logout":
      await fetch("api/logout", { method: "POST", headers: { "X-Eden-Admin": "1" } });
      return showLogin();
    case "rollback": {
      const ok = await confirmDialog({
        title: "设为当前版本？",
        message: "云端会新增一个指向该快照的版本，作为最新存档；原有历史全部保留。设备需执行“下载最新云存档”才会应用到本地。",
        confirm: "设为当前版本",
      });
      if (!ok) return;
      if (await guarded(() => api(`scopes/${encodeURIComponent(scopeID)}/rollback`, { method: "POST", body: { snapshot: id } }), "已恢复为当前版本")) await refresh();
      return;
    }
    case "pin": {
      const pinned = target.dataset.pinned !== "1";
      if (await guarded(() => api(`scopes/${encodeURIComponent(scopeID)}/snapshots/${encodeURIComponent(id)}`,
        { method: "PATCH", body: { pinned } }), pinned ? "已固定快照" : "已取消固定")) await refresh();
      return;
    }
    case "delete-snapshot": {
      const ok = await confirmDialog({
        title: "删除快照？", danger: true, confirm: "删除",
        message: "该快照记录将被永久删除，其加密对象若未被其他快照引用，会在下次清理时回收。此操作无法撤销。",
      });
      if (!ok) return;
      if (await guarded(() => api(`scopes/${encodeURIComponent(scopeID)}/snapshots/${encodeURIComponent(id)}`, { method: "DELETE" }), "快照已删除")) await refresh();
      return;
    }
    case "delete-scope": {
      const ok = await confirmDialog({
        title: "删除整个存档范围？", danger: true, confirm: "永久删除",
        message: `将删除 <b>${esc(scopeTitle(scopeID))}</b> 的全部 ${store.scopeDetail.snapshots.length} 个快照记录。设备本地存档不受影响，但下次同步时会作为新存档重新上传。此操作无法撤销。`,
      });
      if (!ok) return;
      if (await guarded(() => api(`scopes/${encodeURIComponent(scopeID)}`, { method: "DELETE" }), "存档范围已删除")) {
        store.scopeDetail = null;
        location.hash = "#/saves";
      }
      return;
    }
    case "rename-device": {
      const device = deviceByID(id);
      const alias = await promptDialog({
        title: "重命名设备", label: "显示名称", value: device?.alias || "", placeholder: device?.name || "设备名称",
        hint: "留空则使用客户端上报的名称。",
      });
      if (alias === null) return;
      if (await guarded(() => api(`devices/${encodeURIComponent(id)}`, { method: "PATCH", body: { alias } }), "已更新设备名称")) await refresh();
      return;
    }
    case "delete-device": {
      const ok = await confirmDialog({
        title: "移除设备记录？", danger: true, confirm: "移除",
        message: "仅从列表中移除该设备的记录，不会吊销访问权限；该设备再次连接时会重新出现。如需阻止访问，请更换同步令牌。",
      });
      if (!ok) return;
      if (await guarded(() => api(`devices/${encodeURIComponent(id)}`, { method: "DELETE" }), "设备记录已移除")) await refresh();
      return;
    }
    case "prune-preview":
    case "prune-run": {
      const dry = action === "prune-preview";
      if (!dry) {
        const ok = await confirmDialog({
          title: "立即清理存储？", danger: true, confirm: "清理",
          message: "将按保留策略删除过期快照并回收未引用的对象。建议先预览。",
        });
        if (!ok) return;
      }
      target.disabled = true;
      const report = await guarded(() => api(`maintenance/prune${dry ? "?dry_run=1" : ""}`, { method: "POST" }));
      target.disabled = false;
      if (report) { store.pruneReport = report; if (!dry) await loadOverview(); renderMaintenance(); }
      return;
    }
    case "verify": {
      target.disabled = true;
      target.innerHTML = `${icon("shield")}校验中…`;
      const report = await guarded(() => api("maintenance/verify", { method: "POST" }));
      if (report) { store.verifyReport = report; renderMaintenance(); }
      else { target.disabled = false; target.innerHTML = `${icon("shield")}开始校验`; }
      return;
    }
  }
}

// ---------- theme ----------

function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
  const dark = theme ? theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  const button = $('[data-action="theme"]');
  if (button) button.innerHTML = icon(dark ? "sun" : "moon");
}

function toggleTheme() {
  const current = document.documentElement.dataset.theme
    || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const next = current === "dark" ? "light" : "dark";
  storageSet("eden-syncd-theme", next);
  applyTheme(next);
}

// ---------- session ----------

function showLogin() {
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#login-token").value = "";
  $("#login-token").focus();
}

async function showApp() {
  $("#login").hidden = true;
  $("#app").hidden = false;
  main.innerHTML = `<div class="skeleton"></div>`;
  await refresh();
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = $("#login-error");
  const button = event.target.querySelector("button");
  error.textContent = "";
  button.disabled = true;
  try {
    const response = await fetch("api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Eden-Admin": "1" },
      body: JSON.stringify({ token: $("#login-token").value }),
    });
    if (!response.ok) {
      let message = "登录失败";
      try { message = translateError((await response.json()).error); } catch { /* ignore */ }
      error.textContent = message;
      return;
    }
    await showApp();
  } catch {
    error.textContent = "无法连接到服务";
  } finally {
    button.disabled = false;
  }
});

document.addEventListener("click", onAction);
window.addEventListener("hashchange", () => {
  if (!$("#app").hidden) render().catch((error) => {
    if (error instanceof UnauthorizedError) showLogin();
    else toast(error.message, true);
  });
  main.focus({ preventScroll: true });
  window.scrollTo(0, 0);
});
setInterval(() => {
  if (!document.hidden && !$("#app").hidden && $("#modal-root").hidden) refresh({ quiet: true });
}, 20000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && !$("#app").hidden && $("#modal-root").hidden) refresh({ quiet: true });
});

// Inline handlers are blocked by the CSP, so broken cover images are removed here.
document.addEventListener("error", (event) => {
  if (event.target instanceof HTMLImageElement && event.target.closest(".cover")) event.target.remove();
}, true);

applyTheme(storageGet("eden-syncd-theme"));
(async () => {
  try {
    const response = await fetch("api/session", { credentials: "same-origin" });
    const session = await response.json();
    if (session.authenticated) await showApp();
    else showLogin();
  } catch {
    showLogin();
  }
})();
