// Dashboard rendering. Owner: E.
//
// UI only. Every number, chart and node on screen is computed from what the Blindspot
// API returns (api.js), which only knows what agents on real computers reported.
// Nothing here invents data; empty fleets show empty states.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const DECISION = { quarantine: "Quarantine", block: "Block", contain: "Contain", review: "Review", allow: "Allow" };
const SW_STATUS = { blocked: "Blocked", review: "Review", allowed: "Allowed", unreviewed: "Not reviewed" };
const GUARD_STATE = { quarantined: "Quarantined", pinned: "Pinned", "not pinned": "Not pinned" };
const DEC_ORDER = ["quarantine", "block", "review", "contain", "allow"];

const C = { red: "#ffc77a", orange: "#dca666", amber: "#edb16b", green: "#56b7aa", blue: "#9bafb8", violet: "#809eaa", slate: "#64747f", pink: "#72e2cf", sky: "#82bcb9" };
const DEC_COLOR = { quarantine: C.amber, block: C.red, review: C.violet, contain: C.blue, allow: C.green };
const SEV_COLOR = { Critical: C.red, High: C.orange, Medium: C.blue, Low: C.green, Note: C.slate };
const SW_COLOR = { blocked: C.red, review: C.violet, allowed: C.green, unreviewed: C.slate };
const RISK = {
  quarantine: { label: "Quarantine", color: C.amber },
  block: { label: "Needs action", color: C.red },
  review: { label: "Review", color: C.violet },
  contain: { label: "Contained", color: C.blue },
  allow: { label: "Clean", color: C.green },
  none: { label: "No extensions", color: C.slate },
};
const RISK_ORDER = ["quarantine", "block", "review", "contain", "allow", "none"];
const BANDS = [
  { key: "none", label: "No CVE", min: -1, max: 0, color: C.slate },
  { key: "low", label: "Low", min: 0, max: 3.95, color: C.green },
  { key: "medium", label: "Medium", min: 3.95, max: 6.95, color: C.blue },
  { key: "high", label: "High", min: 6.95, max: 8.95, color: C.orange },
  { key: "critical", label: "Critical", min: 8.95, max: 10, color: C.red },
];

const VIEWS = ["overview", "extensions", "machines", "software", "guard", "crown", "alerts", "add"];
const VIEW_META = {
  overview: ["Overview", "See what needs attention across your computers."],
  extensions: ["Extensions", "Find extensions and see why each one was flagged or allowed."],
  machines: ["Machines", "Computers reporting to this server. Pick one to see what runs on it."],
  software: ["Software", "Find installed programs, known vulnerabilities, and available fixes."],
  guard: ["Guard", "Pins approved builds and quarantines updates that gain access."],
  crown: ["Critical systems", "Blast radius: which extensions could read your most sensitive systems."],
  alerts: ["Alerts", "Get a Telegram message the moment something needs you."],
  add: ["Add a computer", "Deploy the agent on a computer and watch it report."],
};
const VIEW_ICON = { overview: "grid", extensions: "puzzle", machines: "monitor", software: "package", guard: "shield", crown: "target", alerts: "bell", add: "plus" };

const state = {
  view: "overview", summary: null, extensions: [], machines: [], software: [], guard: null, exposure: [],
  ext: null, machine: null, sw: null,
  extSort: { key: "score", dir: -1 }, extAction: "",
  swSort: { key: "cvss", dir: -1 }, swStatus: "", swBand: "", swQuick: "",
  mMode: store("bs-mmode") || "map", mFilter: "all", mOs: "", meta: new Map(),
};

function store(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(key);
    localStorage.setItem(key, value);
  } catch { /* storage unavailable */ }
  return null;
}

// ------------------------------------------------------------------ icons

const P = {
  grid: '<rect x="3" y="3" width="7" height="9" rx="2"/><rect x="14" y="3" width="7" height="5" rx="2"/><rect x="14" y="12" width="7" height="9" rx="2"/><rect x="3" y="16" width="7" height="5" rx="2"/>',
  puzzle: '<path d="M19.4 13.1a2.5 2.5 0 1 0 0-2.2V7a1 1 0 0 0-1-1h-3.9a2.5 2.5 0 1 0-2.2 0H8.4a1 1 0 0 0-1 1v3.9a2.5 2.5 0 1 0 0 2.2V17a1 1 0 0 0 1 1h3.9a2.5 2.5 0 1 1 2.2 0h3.9a1 1 0 0 0 1-1z"/>',
  monitor: '<rect x="2.5" y="4" width="19" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
  package: '<path d="m12 2.8 8.5 4.7v9L12 21.2l-8.5-4.7v-9z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9.2M7.8 5.1l8.5 4.7"/>',
  shield: '<path d="M12 2.5 4 5.5v6c0 5 3.4 8.8 8 10 4.6-1.2 8-5 8-10v-6z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.2" fill="currentColor"/>',
  bell: '<path d="M6 8a6 6 0 1 1 12 0c0 7 3 8 3 8H3s3-1 3-8"/><path d="M10.3 20a2 2 0 0 0 3.4 0"/>',
  plus: '<circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/>',
  file: '<path d="M14 2.5H6.5a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V8z"/><path d="M14 2.5V8h5.5M8.5 13h7M8.5 17h5"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5M4 20h16"/>',
  chevrons: '<path d="m11 17-5-5 5-5M18 17l-5-5 5-5"/>',
  chev: '<path d="m9 6 6 6-6 6"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  alert: '<path d="M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  cpu: '<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
  activity: '<path d="M22 12h-4l-3 8L9 4l-3 8H2"/>',
  zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9z"/>',
  map: '<circle cx="12" cy="12" r="2.5"/><circle cx="4.5" cy="6" r="1.8"/><circle cx="19.5" cy="6" r="1.8"/><circle cx="4.5" cy="18" r="1.8"/><circle cx="19.5" cy="18" r="1.8"/><path d="m6 7.2 4 3.2M18 7.2l-4 3.2M6 16.8l4-3.2M18 16.8l-4-3.2"/>',
  tiles: '<rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="8" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/><rect x="13" y="13" width="8" height="8" rx="2"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="3.5" cy="6" r="1" fill="currentColor"/><circle cx="3.5" cy="12" r="1" fill="currentColor"/><circle cx="3.5" cy="18" r="1" fill="currentColor"/>',
  radar: '<path d="M19.1 4.9A10 10 0 1 0 22 12"/><path d="M16.2 7.8A6 6 0 1 0 18 12"/><circle cx="12" cy="12" r="1.6" fill="currentColor"/><path d="m12 12 7-7"/>',
  windows: '<path d="M3 5.5 10.5 4.5v7H3zM13 4.2 21 3v8.5h-8zM3 13h7.5v6.8L3 18.8zM13 13h8v8l-8-1.2z"/>',
  apple: '<path d="M16.4 12.6c0-2.3 1.9-3.4 2-3.5-1.1-1.6-2.8-1.8-3.4-1.8-1.4-.1-2.8.9-3.5.9-.7 0-1.8-.9-3-.8-1.5 0-3 .9-3.8 2.3-1.6 2.8-.4 7 1.2 9.3.8 1.1 1.7 2.4 2.9 2.3 1.2 0 1.6-.7 3-.7s1.8.7 3 .7c1.3 0 2.1-1.1 2.8-2.3.9-1.3 1.3-2.6 1.3-2.6s-2.5-1-2.5-3.8zM14.1 5.8c.6-.8 1.1-1.9 1-3-.9 0-2.1.6-2.8 1.4-.6.7-1.1 1.8-1 2.9 1.1.1 2.1-.5 2.8-1.3z"/>',
  linux: '<path d="M4 6.5h16M4 17.5h16"/><rect x="3" y="3.5" width="18" height="17" rx="2.5"/><path d="m7.5 10 2.5 2-2.5 2M12 14.5h4"/>',
  chrome: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M12 8.5h8.2M9 13.8 4.9 6.7M15 13.8l-4.1 7.1"/>',
  send: '<path d="M21.5 3.5 2.5 10.8l7 2.7 2.7 7z"/><path d="m21.5 3.5-12 10"/>',
  copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7"/>',
  bug: '<rect x="7" y="7" width="10" height="13" rx="5"/><path d="M12 11v9M7 12H3M21 12h-4M7 17H4M20 17h-3M8.5 7 7 4.5M15.5 7 17 4.5M7 8.5 4 6.5M17 8.5l3-2"/>',
  flame: '<path d="M12 22c4 0 7-2.8 7-7 0-4.5-4-7-4-11-3 1.5-5 4.5-5 7-1-1-1.5-2-1.5-3C6 10 5 12.5 5 15c0 4.2 3 7 7 7z"/>',
  remote: '<rect x="2.5" y="4" width="13" height="10" rx="1.5"/><rect x="11.5" y="10" width="10" height="10" rx="1.5"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
  server: '<rect x="3" y="3.5" width="18" height="7" rx="2"/><rect x="3" y="13.5" width="18" height="7" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
  pin: '<path d="M12 22s7-6.2 7-12a7 7 0 0 0-14 0c0 5.8 7 12 7 12z"/><circle cx="12" cy="10" r="2.5"/>',
  cols: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M13 4v16"/>',
  rows: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 12h18"/>',
  wave: '<path d="M2 12c2.5-5 5-5 7.5 0s5 5 7.5 0 3.5-4 5-2"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
};
const icon = (name) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || P.grid}</svg>`;
const ic = (name) => `<i data-icon="${name}">${icon(name)}</i>`;
function hydrateIcons(root = document) {
  $$("[data-icon]:empty", root).forEach((el) => { el.innerHTML = icon(el.dataset.icon); });
}

// ------------------------------------------------------------------ small pieces

function tag(kind, label) {
  const cls = String(kind).replace(/\s+/g, "-");
  const text = esc(label ?? DECISION[kind] ?? SW_STATUS[kind] ?? GUARD_STATE[kind] ?? kind);
  return cls === "quarantine" || cls === "quarantined"
    ? `<span class="tag ${cls}"><span>${text}</span></span>`
    : `<span class="tag ${cls}">${text}</span>`;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many || one + "s"}`;
}

function listText(items, max = 2) {
  if (items.length <= max) return items.join(" and ");
  return `${items.slice(0, max).join(", ")} and ${items.length - max} more`;
}

function time(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
}

function ago(iso) {
  if (!iso) return "never";
  const d = new Date(iso);
  if (isNaN(d)) return "";
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

function download(name, text, type = "application/json") {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([text], { type }));
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function toast(message) {
  $$(".toast").forEach((t) => t.remove());
  const el = document.createElement("div");
  el.className = "toast";
  el.setAttribute("role", "status");
  el.innerHTML = `${ic("zap")}<span></span>`;
  el.querySelector("span").textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 5200);
}

function severityOf(r) {
  return (r.rating && r.rating.severity) || r.severity || { high: "High", medium: "Medium", low: "Low" }[r.level];
}

const sevColor = (sev) => SEV_COLOR[sev] || C.slate;
const bandOf = (v) => (!v ? BANDS[0] : BANDS.find((b) => v > b.min && v <= b.max) || BANDS[4]);
const pct = (n, d) => (d ? Math.round((n / d) * 100) : 0);
const initials = (h) => String(h).replace(/[^A-Za-z0-9]/g, " ").trim().split(/\s+/).slice(0, 2).map((w) => w[0]).join("").toUpperCase() || "?";
const sum = (arr, f) => arr.reduce((n, x) => n + (f ? f(x) : x), 0);

function osKind(os) {
  const s = String(os || "").toLowerCase();
  if (s.includes("windows")) return "windows";
  if (s.includes("mac") || s.includes("darwin")) return "apple";
  if (s) return "linux";
  return "linux";
}
const OS_LABEL = { windows: "Windows", apple: "macOS", linux: "Linux" };

// counts animate from their previous value
const counted = new Map();
function countUp(root = document) {
  $$("[data-count]", root).forEach((el) => {
    const to = Number(el.dataset.count) || 0;
    const key = el.dataset.ck;
    const from = key && counted.has(key) ? counted.get(key) : 0;
    if (key) counted.set(key, to);
    const suffix = el.dataset.suffix || "";
    if (from === to || matchMedia("(prefers-reduced-motion: reduce)").matches) { el.textContent = to.toLocaleString() + suffix; return; }
    const t0 = performance.now(), dur = 900;
    const step = (t) => {
      const k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 3);
      el.textContent = Math.round(from + (to - from) * e).toLocaleString() + suffix;
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}

// ------------------------------------------------------------------ chart pieces (SVG, no libraries)

function ring(value, max, color, { size = 44, stroke = 4, label = value, sub = "" } = {}) {
  const r = (size - stroke) / 2, c = 2 * Math.PI * r;
  const p = max ? Math.max(0, Math.min(1, value / max)) : 0;
  return `<span class="ring" style="width:${size}px;height:${size}px;color:${color}"><svg viewBox="0 0 ${size} ${size}" aria-hidden="true">
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" class="ring-bg" stroke-width="${stroke}"/>
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" class="ring-fg" stroke="${color}" stroke-width="${stroke}"
      stroke-dasharray="${c.toFixed(2)}" stroke-dashoffset="${(c * (1 - p)).toFixed(2)}" style="--c:${c.toFixed(2)}"/></svg>
    <b style="color:${color}">${esc(label)}</b>${sub ? `<small>${esc(sub)}</small>` : ""}</span>`;
}

function donut(id, segs, { size = 160, thick = 16, sub = "" } = {}) {
  const total = sum(segs, (s) => s.value);
  const r = (size - thick) / 2, c = 2 * Math.PI * r;
  const shown = segs.filter((s) => s.value);
  const gap = shown.length > 1 ? 4 : 0;
  let start = 0;
  const arcs = shown.map((s, i) => {
    const len = (s.value / total) * c;
    const out = `<circle class="seg-arc" data-donut="${id}" data-key="${esc(s.key)}" cx="${size / 2}" cy="${size / 2}" r="${r}"
      stroke="${s.color}" color="${s.color}" stroke-width="${thick}" stroke-linecap="butt"
      stroke-dasharray="${Math.max(len - gap, 0.5).toFixed(2)} ${c.toFixed(2)}" stroke-dashoffset="${(-start).toFixed(2)}"
      style="--c:${c.toFixed(2)};animation-delay:${i * 90}ms" data-tip="${esc(s.label)}: ${s.value} (${pct(s.value, total)}%)"></circle>`;
    start += len;
    return out;
  }).join("");
  const legend = segs.map((s) => `<button class="lg" type="button" data-donut="${id}" data-key="${esc(s.key)}" ${s.value ? "" : "disabled"}>
      <i style="background:${s.color}"></i><span>${esc(s.label)}</span><b>${s.value}</b></button>`).join("");
  return `<div class="donut" data-donut-root="${id}">
    <div class="donut-chart" style="width:${size}px;height:${size}px">
      <svg viewBox="0 0 ${size} ${size}"><circle class="ring-bg" cx="${size / 2}" cy="${size / 2}" r="${r}" stroke-width="${thick}"/>${arcs}</svg>
      <div class="donut-c"><b data-count="${total}" data-ck="donut-${id}">0</b><span>${esc(sub)}</span></div>
    </div>
    <div class="legend">${legend}</div></div>`;
}

let gaugeId = 0;
function gauge(p, { label, sub = "", stops = [C.green, C.amber, C.red] } = {}) {
  const v = Math.max(0, Math.min(100, p));
  const id = `gg${++gaugeId}`;
  const a = Math.PI * (1 - v / 100);
  const kx = 100 + 84 * Math.cos(a), ky = 104 - 84 * Math.sin(a);
  const ticks = Array.from({ length: 11 }, (_, i) => {
    const t = Math.PI * (1 - i / 10);
    return `<line class="g-tick" x1="${100 + 66 * Math.cos(t)}" y1="${104 - 66 * Math.sin(t)}" x2="${100 + 71 * Math.cos(t)}" y2="${104 - 71 * Math.sin(t)}"/>`;
  }).join("");
  return `<div class="gauge"><svg viewBox="0 0 200 116" aria-hidden="true">
      <defs><linearGradient id="${id}" x1="0" x2="1"><stop offset="0" stop-color="${stops[0]}"/><stop offset=".5" stop-color="${stops[1]}"/><stop offset="1" stop-color="${stops[2]}"/></linearGradient></defs>
      <path d="M16 104 A84 84 0 0 1 184 104" class="g-bg" pathLength="100"/>
      <path d="M16 104 A84 84 0 0 1 184 104" class="g-fg" pathLength="100" stroke="url(#${id})" stroke-dasharray="${v} 100"/>
      ${ticks}
      ${v > 0 ? `<circle class="g-knob" cx="${kx.toFixed(1)}" cy="${ky.toFixed(1)}" r="6" stroke="url(#${id})"/>` : ""}
    </svg><div class="g-c"><b>${label}</b><span class="gs">${esc(sub)}</span></div></div>`;
}

function radar(entries, max = 9, size = 220) {
  const n = entries.length;
  if (n < 3) return "";
  const cx = size / 2, cy = size / 2, R = size / 2 - 44;
  const pt = (i, r) => {
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / n;
    return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  };
  const poly = (r) => entries.map((_, i) => pt(i, r).map((x) => x.toFixed(1)).join(",")).join(" ");
  const grid = [1 / 3, 2 / 3, 1].map((f) => `<polygon class="r-grid" points="${poly(R * f)}"/>`).join("");
  const axes = entries.map((_, i) => { const [x, y] = pt(i, R); return `<line class="r-axis" x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"/>`; }).join("");
  const area = entries.map(([, v], i) => pt(i, (Math.max(0, Math.min(max, v)) / max) * R).map((x) => x.toFixed(1)).join(",")).join(" ");
  const dots = entries.map(([, v], i) => { const [x, y] = pt(i, (Math.max(0, Math.min(max, v)) / max) * R); return `<circle class="r-pt" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2.6"/>`; }).join("");
  const labels = entries.map(([k, v], i) => {
    const [x, y] = pt(i, R + 12);
    const anchor = Math.abs(x - cx) < 6 ? "middle" : x > cx ? "start" : "end";
    return `<text x="${x.toFixed(1)}" y="${(y + 3).toFixed(1)}" text-anchor="${anchor}">${esc(k)}</text>`;
  }).join("");
  return `<svg class="radar" viewBox="0 0 ${size} ${size}" role="img" aria-label="OWASP factors">
    <defs><linearGradient id="radarStroke" x1="0" x2="1"><stop offset="0" stop-color="${C.pink}"/><stop offset="1" stop-color="${C.blue}"/></linearGradient></defs>
    ${grid}${axes}<polygon class="r-area" points="${area}"/>${dots}${labels}</svg>`;
}

function stackBar(parts, total) {
  const t = total || sum(parts, (p) => p.value);
  if (!t) return `<div class="stack"></div>`;
  return `<div class="stack">${parts.filter((p) => p.value).map((p, i) =>
    `<i style="flex:${p.value};background:${p.color};animation-delay:${i * 80}ms" data-tip="${esc(p.label)}: ${p.value}"></i>`).join("")}</div>`;
}

function stackLegend(parts) {
  return `<div class="stack-legend">${parts.filter((p) => p.value).map((p) => `<span><i style="background:${p.color}"></i>${esc(p.label)} <b>${p.value}</b></span>`).join("")}</div>`;
}

function matrix(rt) {
  const order = ["LOW", "MEDIUM", "HIGH"];
  const color = { "LOW-LOW": C.slate, "LOW-MEDIUM": C.green, "LOW-HIGH": C.amber, "MEDIUM-LOW": C.green, "MEDIUM-MEDIUM": C.amber, "MEDIUM-HIGH": C.orange, "HIGH-LOW": C.amber, "HIGH-MEDIUM": C.orange, "HIGH-HIGH": C.red };
  let cells = "";
  for (const impact of ["HIGH", "MEDIUM", "LOW"]) {
    for (const like of order) {
      const on = rt.impact_level === impact && rt.likelihood_level === like;
      const col = color[`${impact}-${like}`];
      cells += `<i class="${on ? "on" : ""}" style="background:${col};color:${col}" data-tip="Impact ${impact.toLowerCase()}, likelihood ${like.toLowerCase()}"></i>`;
    }
  }
  return `<div class="matrix" role="img" aria-label="OWASP matrix: impact ${rt.impact_level}, likelihood ${rt.likelihood_level}">
    <span class="yl">impact</span>${cells}<span></span><span class="xl">likelihood</span></div>`;
}

function kpi({ key, label, value, sub = "", iconName, color, goto, filter, on = false, suffix = "" }) {
  const attrs = goto ? `data-goto="${goto}"` : filter ? `data-kfilter="${filter}"` : "disabled";
  return `<button class="kpi ${on ? "on" : ""}" type="button" ${attrs} style="--accent:${color}">
    <span class="kpi-l">${esc(label)}</span><span class="kpi-ic">${ic(iconName)}</span>
    <b class="kpi-v" data-count="${value}" data-ck="${key}" data-suffix="${suffix}">0</b>
    <span class="kpi-s">${sub}</span></button>`;
}

// ------------------------------------------------------------------ derived data (all from API rows)

function computeMeta() {
  const meta = new Map();
  for (const m of state.machines) meta.set(m.hostname, { dec: { quarantine: 0, block: 0, review: 0, contain: 0, allow: 0 }, worst: 0, worstSev: null, exts: [] });
  for (const e of state.extensions) {
    for (const host of e.machines || []) {
      const m = meta.get(host);
      if (!m) continue;
      m.dec[e.recommendation] = (m.dec[e.recommendation] || 0) + 1;
      m.exts.push(e);
      if (e.score > m.worst) { m.worst = e.score; m.worstSev = e.severity; }
    }
  }
  state.meta = meta;
}

function riskOf(m) {
  const x = state.meta.get(m.hostname);
  if (m.quarantined) return "quarantine";
  if (m.software_blocked || (x && x.dec.block) || m.high_risk) return "block";
  if (x && x.dec.review) return "review";
  if (x && x.dec.contain) return "contain";
  if (!m.extensions) return "none";
  return "allow";
}

function decParts(dec) {
  return DEC_ORDER.map((k) => ({ key: k, label: DECISION[k], value: dec[k] || 0, color: DEC_COLOR[k] }));
}

// ------------------------------------------------------------------ action bar + nav

function renderActionbar() {
  const s = state.summary;
  const swBlocked = state.software.filter((x) => x.status === "blocked");
  const swMachines = swBlocked.reduce((n, x) => n + x.machines, 0);
  const items = [];
  if (s.quarantined) items.push(["tape", "alert", s.quarantined, `extension ${s.quarantined === 1 ? "build" : "builds"} quarantined by Guard`, () => go("guard")]);
  if (s.by_recommendation.block) items.push(["red", "flame", s.by_recommendation.block, `${s.by_recommendation.block === 1 ? "extension" : "extensions"} to block`, () => { go("extensions"); setExtAction("block"); }]);
  if (swBlocked.length) items.push(["red", "bug", swMachines, `${swMachines === 1 ? "machine runs" : "machines run"} blocked software`, () => { go("software"); state.swStatus = "blocked"; renderSoftwareView(); }]);
  if (s.crown_jewel_exposed) items.push(["blue", "target", s.crown_jewel_exposed, `${s.crown_jewel_exposed === 1 ? "extension can" : "extensions can"} reach critical systems`, () => go("crown")]);
  if (!s.machines) items.push(["blue", "plus", "0", "computers have reported. Add the first one", () => go("add")]);
  else if (!items.length) items.push(["calm", "check", "0", "Nothing needs action", null]);
  const bar = $("#actionbar");
  bar.innerHTML = items.map(([cls, i, n, text], k) =>
    `<button class="act ${cls}" data-i="${k}" type="button"><span class="act-ic">${ic(i)}</span><b>${esc(n)}</b><span class="t">${esc(text)}</span></button>`).join("");
  $$("button", bar).forEach((b) => {
    const fn = items[Number(b.dataset.i)][4];
    if (fn) b.addEventListener("click", fn);
  });

  const setCount = (id, n, alert) => {
    const el = $(id);
    el.textContent = n || n === 0 ? n : "";
    el.classList.toggle("alert", Boolean(alert));
    el.closest("button").dataset.alert = String(Boolean(alert));
  };
  setCount("#n-extensions", s.unique_extensions, s.quarantined);
  setCount("#n-machines", s.machines);
  setCount("#n-software", swBlocked.length || s.software_titles, swBlocked.length);
  setCount("#n-guard", s.quarantined || "", s.quarantined);
  setCount("#n-crown", s.crown_jewel_exposed);
}

function go(view) {
  if (!VIEWS.includes(view)) view = "overview";
  const changed = state.view !== view;
  state.view = view;
  document.body.dataset.view = view;
  document.body.classList.remove("static");
  $$(".nav button").forEach((b) => b.setAttribute("aria-current", String(b.dataset.view === view)));
  VIEWS.forEach((v) => $(`#view-${v}`).classList.toggle("hidden", v !== view));
  if (changed) {
    const sec = $(`#view-${view}`);
    sec.style.animation = "none"; void sec.offsetWidth; sec.style.animation = "";
  }
  const [title, sub] = VIEW_META[view];
  $("#page-title").textContent = title;
  $("#crumb-view").textContent = title;
  $("#page-sub").textContent = sub;
  $(".display-options").open = false;
  history.replaceState(null, "", `#${view}`);
  moveGlow();
  window.scrollTo({ top: 0 });
}

function moveGlow() {
  const b = $(".nav button[aria-current='true']");
  const glow = $(".nav-glow");
  if (!b || !glow) return;
  glow.style.opacity = "1";
  glow.style.transform = `translateY(${b.offsetTop}px)`;
  glow.style.height = `${b.offsetHeight}px`;
}


// ------------------------------------------------------------------ top alert bar (harmful extensions)

const alertbar = { items: [], i: 0, timer: null, hover: false, sig: "" };

function session(key, value) {
  try {
    if (value === undefined) return sessionStorage.getItem(key);
    sessionStorage.setItem(key, value);
  } catch { /* storage unavailable */ }
  return null;
}

function renderAlertbar() {
  const harmful = state.extensions
    .filter((e) => e.recommendation === "quarantine" || e.recommendation === "block")
    .sort((a, b) => (b.recommendation === "quarantine") - (a.recommendation === "quarantine") || b.score - a.score);
  const sig = harmful.map((e) => `${e.id}@${e.version}:${e.recommendation}`).join("|");
  document.title = harmful.length ? `(${harmful.length}) ⚠ Blindspot` : "Blindspot";
  const bar = $("#alertbar");
  const isNew = sig !== alertbar.sig;
  alertbar.sig = sig;
  alertbar.items = harmful;
  if (!harmful.length || session("bs-alert-dismissed") === sig) {
    bar.classList.add("hidden");
    clearInterval(alertbar.timer);
    return;
  }
  if (isNew) alertbar.i = 0;
  alertbar.i = Math.min(alertbar.i, harmful.length - 1);
  const wasHidden = bar.classList.contains("hidden");
  bar.classList.remove("hidden");
  if (wasHidden || isNew) { bar.style.animation = "none"; void bar.offsetWidth; bar.style.animation = ""; }
  drawAlert(false);
  clearInterval(alertbar.timer);
  if (harmful.length > 1) {
    alertbar.timer = setInterval(() => {
      if (alertbar.hover || document.visibilityState !== "visible") return;
      alertbar.i = (alertbar.i + 1) % alertbar.items.length;
      drawAlert(true);
    }, 8000);
  }
}

function drawAlert(swap) {
  const e = alertbar.items[alertbar.i];
  if (!e) return;
  const q = e.recommendation === "quarantine";
  const n = alertbar.items.length;
  const bar = $("#alertbar");
  bar.classList.toggle("q", q);
  bar.innerHTML = `
    <span class="ab-ic">${ic("alert")}</span>
    <div class="ab-body ${swap ? "ab-swap" : ""}">
      <div class="ab-k">${q ? "Hijacked update quarantined" : "Harmful extension detected"}${n > 1 ? ` · ${alertbar.i + 1} of ${n}` : ""}</div>
      <div class="ab-main"><b class="n">${esc(e.name)}</b> ${tag(e.recommendation)}
        <span class="sc" style="color:${sevColor(e.severity)}">${esc(e.score)}</span>
        <span class="why">${esc(severityOf(e))} · on ${plural(e.installs, "machine")} · ${esc(q ? "New build differs from the approved one" : e.top_finding)}</span></div>
    </div>
    ${n > 1 ? `<div class="ab-pager"><button class="ab-prev" type="button" title="Previous">${ic("chev")}</button>${alertbar.i + 1}/${n}<button class="ab-next" type="button" title="Next">${ic("chev")}</button></div>` : "<span></span>"}
    <button class="btn small ab-go" type="button">Investigate</button>
    <button class="ab-x" type="button" title="Hide until something changes">${ic("x")}</button>`;
}

function bindAlertbar() {
  const bar = $("#alertbar");
  bar.addEventListener("pointerenter", () => { alertbar.hover = true; });
  bar.addEventListener("pointerleave", () => { alertbar.hover = false; });
  bar.addEventListener("click", (ev) => {
    const n = alertbar.items.length;
    if (ev.target.closest(".ab-prev")) { alertbar.i = (alertbar.i - 1 + n) % n; drawAlert(true); return; }
    if (ev.target.closest(".ab-next")) { alertbar.i = (alertbar.i + 1) % n; drawAlert(true); return; }
    if (ev.target.closest(".ab-x")) { session("bs-alert-dismissed", alertbar.sig); bar.classList.add("hidden"); clearInterval(alertbar.timer); return; }
    if (ev.target.closest(".ab-go")) {
      const e = alertbar.items[alertbar.i];
      go("extensions");
      renderExtDetail(e.id);
    }
  });
}

// ------------------------------------------------------------------ view options (layout, motion)

function applyViewOptions() {
  const layout = store("bs-layout") || "h";
  const calm = store("bs-motion") === "calm";
  document.body.classList.toggle("layout-v", layout === "v");
  document.body.classList.toggle("calm", calm);
  $$("#layout-seg button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.layout === layout)));
  $("#motion-btn").setAttribute("aria-pressed", String(calm));
}

function bindViewOptions() {
  $("#layout-seg").addEventListener("click", (e) => {
    const b = e.target.closest("[data-layout]");
    if (!b) return;
    store("bs-layout", b.dataset.layout);
    applyViewOptions();
    toast(b.dataset.layout === "v" ? "Detail panel below the list." : "Detail panel beside the list.");
  });
  $("#motion-btn").addEventListener("click", () => {
    const calm = store("bs-motion") !== "calm";
    store("bs-motion", calm ? "calm" : "full");
    applyViewOptions();
    toast(calm ? "Calm motion: looping animations stopped." : "Full motion back on.");
  });
}

// ------------------------------------------------------------------ overview

function renderOverview() {
  const s = state.summary;
  const empty = !s.machines;
  $("#ov-empty").classList.toggle("hidden", !empty);
  $("#ov-body").classList.toggle("hidden", empty);
  if (empty) return;

  const swWithCves = state.software.filter((x) => x.vulnerability_count).length;
  $("#kpis").innerHTML = [
    kpi({ key: "k-m", label: "Machines", value: s.machines, sub: `reporting · last ${esc(ago(s.last_seen))}`, iconName: "monitor", color: C.sky, goto: "machines" }),
    kpi({ key: "k-e", label: "Extensions", value: s.unique_extensions, sub: `unique · ${s.extensions_installed} installs`, iconName: "puzzle", color: C.violet, goto: "extensions" }),
    kpi({ key: "k-h", label: "High-risk installs", value: s.installs_at_high_risk, sub: `${pct(s.installs_at_high_risk, s.extensions_installed)}% of all installs`, iconName: "flame", color: s.installs_at_high_risk ? C.red : C.slate, goto: "extensions" }),
    kpi({ key: "k-q", label: "Quarantined", value: s.quarantined, sub: s.quarantined ? "hijacked-update pattern" : "no drift detected", iconName: "shield", color: s.quarantined ? C.amber : C.slate, goto: "guard" }),
    kpi({ key: "k-s", label: "Software", value: s.software_titles, sub: `titles · ${swWithCves} with CVEs${s.software_kev ? `, ${s.software_kev} exploited` : ""}`, iconName: "package", color: C.blue, goto: "software" }),
    kpi({ key: "k-c", label: "Critical reach", value: s.crown_jewel_exposed, sub: `ext. on ${plural(s.machines_with_crown_jewel_exposure, "machine")}`, iconName: "target", color: C.pink, goto: "crown" }),
  ].join("");

  const p = pct(s.installs_at_high_risk, s.extensions_installed);
  $("#ov-gauge").innerHTML = gauge(p, { label: `${p}%`, sub: `${s.installs_at_high_risk} of ${s.extensions_installed} installs` }) +
    `<div class="gauge-stats">
      <div><b data-count="${s.ai_extensions}" data-ck="g-ai">0</b><span>AI extensions</span></div>
      <div><b data-count="${s.machines_with_crown_jewel_exposure}" data-ck="g-cj">0</b><span>machines exposed</span></div>
      <div><b data-count="${(s.software_by_status && s.software_by_status.blocked) || 0}" data-ck="g-sb">0</b><span>software blocked</span></div></div>`;

  $("#ov-decisions").innerHTML = donut("dec", decParts(s.by_recommendation), { sub: "extensions" });
  const sbs = s.software_by_status || {};
  $("#ov-software").innerHTML = donut("sw", ["blocked", "review", "unreviewed", "allowed"].map((k) => ({ key: k, label: SW_STATUS[k], value: sbs[k] || 0, color: SW_COLOR[k] })), { sub: "programs" });

  const top = [...state.extensions].sort((a, b) => b.score - a.score).slice(0, 6);
  $("#ov-top").innerHTML = top.length ? `<div class="toplist">${top.map((e, i) => `
    <button class="top-row" type="button" data-open-ext="${esc(e.id)}">
      <span class="rank">${i + 1}</span>
      <span><span class="nm">${esc(e.name)} ${e.ai ? tag("ai", "AI") : ""} ${tag(e.recommendation)}</span>
        <span class="meter"><i style="width:${e.score}%;background:${sevColor(e.severity)};color:${sevColor(e.severity)};animation-delay:${i * 70}ms"></i></span></span>
      <span class="sc" style="color:${sevColor(e.severity)}">${esc(e.score)}</span>
    </button>`).join("")}</div>` : `<p class="empty">No extensions reported.</p>`;

  const ms = [...state.machines].sort((a, b) => RISK_ORDER.indexOf(riskOf(a)) - RISK_ORDER.indexOf(riskOf(b)) || a.hostname.localeCompare(b.hostname));
  const riskCount = {};
  ms.forEach((m) => { const r = riskOf(m); riskCount[r] = (riskCount[r] || 0) + 1; });
  $("#ov-heat").innerHTML = `<div class="heat">${ms.map((m, i) => {
    const r = riskOf(m);
    return `<button type="button" data-open-machine="${esc(m.machine_id)}" style="--c:${RISK[r].color};--d:${Math.min(i * 25, 900)}ms"
      data-tip="${esc(m.hostname)}\n${esc(m.os)}\n${RISK[r].label} · ${plural(m.extensions, "extension")} · ${plural(m.software ?? 0, "program")}" aria-label="${esc(m.hostname)}"></button>`;
  }).join("")}</div>
    <div class="heat-legend">${RISK_ORDER.filter((r) => riskCount[r]).map((r) => `<span><i style="background:${RISK[r].color}"></i>${RISK[r].label} ${riskCount[r]}</span>`).join("")}</div>`;

  const osCount = {};
  ms.forEach((m) => { const k = osKind(m.os); osCount[k] = (osCount[k] || 0) + 1; });
  const osParts = Object.keys(OS_LABEL).map((k, i) => ({ label: OS_LABEL[k], value: osCount[k] || 0, color: [C.sky, C.pink, C.violet][i] }));
  const worst = [...ms].sort((a, b) => (b.quarantined - a.quarantined) || (b.high_risk + b.software_blocked) - (a.high_risk + a.software_blocked) || b.extensions - a.extensions).slice(0, 3);
  $("#ov-fleet").innerHTML = `<div class="fleet-extra">
    <div><h4>Operating systems</h4>${stackBar(osParts)}${stackLegend(osParts)}</div>
    <div><h4>Most exposed computers</h4><div class="worst">${worst.map((m) => `<button type="button" data-open-machine="${esc(m.machine_id)}" style="--c:${RISK[riskOf(m)].color}">
      <span class="dot"></span><b>${esc(m.hostname)}</b><span class="sub">${m.quarantined ? `${m.quarantined} quarantined · ` : ""}${m.high_risk} high risk · ${plural(m.extensions, "ext")}</span></button>`).join("")}</div></div></div>`;

  const ex = state.exposure || [];
  $("#ov-crown").innerHTML = ex.length ? `<div class="xbars">${ex.map((c) => {
    const dec = {};
    c.extensions.forEach((e) => { dec[e.recommendation] = (dec[e.recommendation] || 0) + 1; });
    return `<button class="xbar" type="button" data-goto="crown">
      <span class="nm">${esc(c.system)}</span>
      ${stackBar(decParts(dec))}
      <span class="v"><b>${c.extension_count}</b>ext · ${plural(c.machine_count, "PC")}</span></button>`;
  }).join("")}</div><div class="stack-legend">${DEC_ORDER.map((k) => `<span><i style="background:${DEC_COLOR[k]}"></i>${DECISION[k]}</span>`).join("")}</div>`
    : `<p class="empty">No critical systems are configured, or nothing can reach them.</p>`;

  $("#ov-log").innerHTML = logItems((state.guard && state.guard.events) || [], 12);
  countUp($("#view-overview"));
}

function logItems(events, max) {
  const KIND = { quarantined: "quarantined", "auto-approved": "approved automatically", baseline: "pinned", approved: "approved", advisory: "arrived", feed: "", "alert-sent": "alert sent", "alert-failed": "alert not sent", "risk-up": "risk rose", cleared: "", "blocked-install": "blocked version installed", "software-approved": "approved", "software-removed": "removed from the approved list" };
  const list = max ? events.slice(0, max) : events;
  return list.map((ev, i) => `
    <li class="lv-${esc(ev.level)}" style="animation-delay:${Math.min(i * 40, 600)}ms"><time datetime="${esc(ev.at)}" title="${esc(ago(ev.at))}">${esc(time(ev.at))}</time>
      <div><b>${esc(ev.subject)}</b> ${esc(KIND[ev.kind] ?? ev.kind)}<br>
      <span class="quiet small">${esc(ev.detail)}</span></div></li>`).join("")
    || `<li class="empty-li">Nothing yet. Events appear as agents report.</li>`;
}

// ------------------------------------------------------------------ extensions

function setExtAction(action) {
  state.extAction = action;
  renderExtSeg();
  renderExtRows();
}

function renderExtSeg() {
  const counts = {};
  state.extensions.forEach((e) => { counts[e.recommendation] = (counts[e.recommendation] || 0) + 1; });
  $("#ext-seg").innerHTML = [["", "All", state.extensions.length, null], ...DEC_ORDER.map((k) => [k, DECISION[k], counts[k] || 0, DEC_COLOR[k]])]
    .filter(([k, , n]) => !k || n || state.extAction === k)
    .map(([k, label, n, col]) => `<button type="button" data-act="${k}" aria-pressed="${state.extAction === k}" ${col ? `style="--c:${col}"` : ""}>${col ? '<i class="dot"></i>' : ""}${label}<em>${n}</em></button>`).join("");
}

function signalBars(sig) {
  if (!sig) return "";
  const names = ["permission", "code", "network", "reputation"];
  return `<span class="signals" data-tip="${names.map((k) => `${k}: ${sig[k] && sig[k].available !== false ? sig[k].score : "n/a"}`).join("\n")}">${names.map((k, i) => {
    const s = sig[k];
    if (!s || s.available === false) return `<i class="na"></i>`;
    const col = s.score >= 70 ? C.red : s.score >= 35 ? C.amber : C.green;
    return `<i style="height:${Math.max(3, Math.round(s.score * 0.22))}px;--c:${col};animation-delay:${i * 60}ms"></i>`;
  }).join("")}</span>`;
}

function avatars(hosts, n) {
  const shown = (hosts || []).slice(0, 3);
  return `<span class="avatars" data-tip="${esc((hosts || []).join("\n"))}">${shown.map((h) => `<span>${esc(initials(h))}</span>`).join("")}<b>${esc(n)}</b></span>`;
}

function renderExtRows() {
  const text = $("#filter").value.trim().toLowerCase();
  const action = state.extAction;
  const { key, dir } = state.extSort;
  const rows = state.extensions.filter(
    (e) => (!action || e.recommendation === action)
      && (!text || e.name.toLowerCase().includes(text) || e.high_risk_permissions.join(" ").toLowerCase().includes(text))
  ).sort((a, b) => {
    const va = key === "recommendation" ? DEC_ORDER.indexOf(a.recommendation) : a[key];
    const vb = key === "recommendation" ? DEC_ORDER.indexOf(b.recommendation) : b[key];
    if (typeof va === "string") return dir * va.localeCompare(vb);
    return dir * ((va ?? 0) - (vb ?? 0));
  });
  $$("#view-extensions th[data-sort]").forEach((th) => {
    th.classList.toggle("sorted", th.dataset.sort === key);
    th.classList.toggle("asc", th.dataset.sort === key && dir === 1);
  });
  $("#ext-rows").innerHTML = rows.map((e, i) => `
    <tr data-key="${esc(e.id)}" style="--i:${Math.min(i, 30)}" class="${state.ext === e.id ? "on" : ""} ${e.recommendation === "quarantine" ? "taped" : ""}">
      <td class="num">${ring(e.score, 100, sevColor(e.severity), { size: 42, stroke: 3.5 })}</td>
      <td><div class="name">${esc(e.name)} ${e.ai ? tag("ai", "AI") : ""}</div>
        <div class="sub clip">${esc(e.recommendation === "quarantine" ? "New build differs from the approved one" : e.top_finding)}</div></td>
      <td class="hide-sm">${signalBars(e.signals)}</td>
      <td>${tag(e.recommendation)}</td>
      <td class="num">${avatars(e.machines, e.installs)}</td>
    </tr>`).join("") || (state.extensions.length
      ? `<tr><td colspan="5" class="empty">No extensions match. Clear the search or pick another decision.</td></tr>`
      : `<tr><td colspan="5" class="empty">No extensions yet. They appear here as soon as a computer reports. <a href="#add" data-goto="add">Add a computer</a></td></tr>`);
}

function verdict(r) {
  const systems = (r.exposure || []).map((e) => e.system);
  const top = (r.findings || []).filter((f) => f.severity !== "info" && f.signal !== "score").slice(0, 2).map((f) => f.title);
  const q = (r.guard && r.guard.quarantined) || [];
  switch (r.recommendation) {
    case "quarantine":
      return `Quarantined. Version ${esc(q[0].version)} is not the build that was approved, and it gained access.` +
        (r.known_good ? " Its ID is on the allowlist, so an ID-based allowlist would have let it through." : "");
    case "block":
      return `Block it. ${esc(top.map((t) => t + ".").join(" "))}` +
        (systems.length ? ` It can read and change ${esc(listText(systems))}.` : "");
    case "contain":
      return `Keep it, but off ${esc(listText(systems))}. It can read ${systems.length === 1 ? "this system" : "these systems"} today; containment removes that access and nothing else.`;
    case "review":
      return `Have someone look at it before allowing it. ${esc(top[0] ? top[0] + "." : "")}`;
    default:
      return r.known_good
        ? `Allowed. On the approved list${r.guard && r.guard.pinned ? " and pinned to the reviewed build" : ""}.`
        : "Allowed. Nothing in its permissions, code or reputation stands out.";
  }
}

function updateDetail(panel, item, render) {
  const open = panel.dataset.item === item
    ? new Set($$("details[open] > summary", panel).map((summary) => summary.textContent))
    : new Set();
  panel.dataset.item = item;
  panel.innerHTML = render;
  $$("details > summary", panel).forEach((summary) => {
    summary.parentElement.open = open.has(summary.textContent);
  });
}

async function renderExtDetail(id) {
  state.ext = id;
  renderExtRows();
  const r = await Api.extension(id);
  const el = $("#ext-detail");
  if (!r) { el.innerHTML = `<p class="empty">This extension is no longer installed anywhere.</p>`; return; }

  const q = (r.guard && r.guard.quarantined) || [];
  const reasons = q.length
    ? q[0].reasons.map((t) => ({ title: t, detail: "" }))
    : (r.findings || []).filter((f) => f.severity !== "info" && f.signal !== "score").slice(0, 3);
  const hot = new Set(["<all_urls>", "cookies", "webRequest", "webRequestBlocking", "debugger", "nativeMessaging", "proxy", "management", "clipboardRead", "history", "scripting"]);
  const perms = (r.capabilities || []).map((c) => {
    const isHot = hot.has(c.permission) || /^\*:\/\/\*\/|^https?:\/\/\*\/|content script/.test(c.permission);
    return `<span class="chip ${isHot ? "hot" : ""}" data-tip="${esc(c.meaning)}">${esc(c.permission)}</span>`;
  }).join("");
  const systems = (r.exposure || []).map((e) => `<span class="chip sys" data-tip="via ${esc(e.via)} ${esc(e.pattern)}">${esc(e.system)}</span>`).join("");
  const sev = severityOf(r);
  const col = sevColor(sev);
  const rt = r.rating;
  const factorEntries = rt ? [...Object.entries(rt.factors.likelihood || {}), ...Object.entries(rt.factors.impact || {})] : [];
  const ratingRow = rt ? `
    <div class="rating-row">
      ${matrix(rt)}
      <div class="small">Rated <b>${esc(rt.raw_severity || rt.severity)}</b> with the OWASP Risk Rating Methodology:
        likelihood ${esc(rt.likelihood)} (${esc(rt.likelihood_level.toLowerCase())}) × impact ${esc(rt.impact)} (${esc(rt.impact_level.toLowerCase())}).
        ${rt.capped ? "Shown as Low because the ID is approved and this build is pinned." : ""}
        ${rt.uncapped_by_guard ? "The approved-ID discount is removed: nobody approved this build." : ""}</div>
    </div>` : "";
  const factorRows = rt ? [["Likelihood", rt.factors.likelihood || {}], ["Impact", rt.factors.impact || {}]].map(([g, f]) =>
    `<span class="grp">${g}</span>` + Object.entries(f).map(([k, v]) => {
      const c = v >= 6 ? C.red : v >= 3 ? C.amber : C.green;
      return `<span>${esc(k)}</span><span class="meter"><i style="width:${(v / 9) * 100}%;background:${c}"></i></span><b>${esc(v)}</b>`;
    }).join("")).join("") : "";
  const allFindings = (r.findings || []).filter((f) => f.severity !== "info" || f.signal === "score");
  const servers = (r.endpoints || []).filter((e) => !e.known).map((e) => `<code>${esc(e.host)}</code>`).join(", ");
  const attack = (r.attack || []).map((t) =>
    `<li><a href="https://attack.mitre.org/techniques/${esc(t.id.replace(".", "/"))}/" target="_blank" rel="noopener"><b>${esc(t.id)}</b></a> ${esc(t.name)} <span class="quiet small">(${esc(t.why)})</span></li>`).join("");
  const installs = (r.installs || []).map((i) =>
    `<button class="chip machine-chip" data-machine="${esc(i.machine_id)}" type="button"><b>${esc(i.hostname)}</b> ${esc(i.version)}${q.some((x) => x.version === i.version) ? " (quarantined build)" : ""}</button>`).join("");

  updateDetail(el, id, `
    <div class="d-head">
      <div><h2>${esc(r.name)} ${r.ai && r.ai.is_ai ? tag("ai", "AI") : ""}</h2>
        <div class="ver">Version ${esc(r.version)}${(r.installed_versions || []).length > 1 ? ` (also ${esc(r.installed_versions.filter((v) => v !== r.version).join(", "))})` : ""}</div></div>
      ${tag(r.recommendation)}
    </div>
    <div class="score-hero">
      ${ring(r.score, 100, col, { size: 96, stroke: 8 })}
      <div class="meta">
        <span class="sev-label" style="color:${col}">${esc(sev)} risk</span>
        ${rt ? `<span class="lxi">likelihood ${esc(rt.likelihood)} × impact ${esc(rt.impact)}</span>` : ""}
        <span class="lxi">${plural((r.installs || []).length, "install")} · ${plural((r.exposure || []).length, "critical system")} reachable</span>
      </div>
    </div>
    <p class="verdict ${esc(r.recommendation)}">${verdict(r)}</p>
    <h3 class="block-title">${q.length ? "What changed" : "Why"}</h3>
    <ul class="reasons">${reasons.map((f) => `<li><b>${esc(f.title)}</b>${f.detail ? `<span>${esc(f.detail)}</span>` : ""}</li>`).join("") || `<li class="quiet">No risk findings.</li>`}</ul>
    ${systems ? `<h3 class="block-title">Can reach</h3><div class="chips">${systems}</div>` : ""}
    <details><summary>Permissions</summary>
    <div class="chips">${perms || `<span class="quiet">None</span>`}</div>
    </details>
    <details><summary>How the score was calculated</summary>
    ${ratingRow}
    ${factorEntries.length >= 3 ? `<h3 class="block-title">Risk factors <span class="quiet small">(OWASP 0 to 9)</span></h3>
      <div class="radar-wrap">${radar(factorEntries)}<div class="factors">${factorRows}</div></div>` : ""}

      ${factorEntries.length < 3 ? `<div class="factors" style="margin:8px 0">${factorRows}</div>` : ""}
      <p class="small quiet">Factors on OWASP's 0 to 9 scale. Each side: 0.6 × strongest factor + 0.4 × average.
        Score = OWASP severity band (Critical 85+, High 70+, Medium 35+, Low 10+), refined by likelihood × impact.</p>
    </details>
    <details><summary>All findings (${allFindings.length})</summary>
      <ul class="reasons">${allFindings.map((f) => `<li><b>${esc(f.title)}</b><span>${esc(f.detail)}</span>${f.evidence ? `<code class="evidence">${esc(f.evidence)}</code>` : ""}</li>`).join("")}</ul>
    </details>
    ${attack ? `<details><summary>MITRE ATT&CK (${(r.attack || []).length})</summary><ul class="reasons attack">${attack}</ul></details>` : ""}
    ${servers ? `<details><summary>Unrecognised servers</summary><p>${servers}</p></details>` : ""}
    <h3 class="block-title">Installed on</h3>
    <div class="chips">${installs || `<span class="quiet">No machine reports it any more.</span>`}</div>`);
  $$("[data-machine]", el).forEach((b) => b.addEventListener("click", () => { go("machines"); renderMachine(b.dataset.machine); }));
}

// ------------------------------------------------------------------ machines

function machineMatches(m) {
  const text = $("#m-filter").value.trim().toLowerCase();
  const r = riskOf(m);
  const f = state.mFilter;
  const okRisk = f === "all"
    || (f === "action" && (r === "quarantine" || r === "block"))
    || (f === "quarantine" && m.quarantined)
    || (f === "software" && m.software_blocked)
    || (f === "clean" && (r === "allow" || r === "contain"))
    || (f.startsWith("risk:") && r === f.slice(5));
  const okOs = !state.mOs || osKind(m.os) === state.mOs;
  const okText = !text || `${m.hostname} ${m.os}`.toLowerCase().includes(text);
  return okRisk && okOs && okText;
}

function renderMachinesView() {
  const ms = state.machines;
  const counts = { action: 0, quarantine: 0, software: 0, clean: 0 };
  const os = {};
  ms.forEach((m) => {
    const r = riskOf(m);
    if (r === "quarantine" || r === "block") counts.action++;
    if (m.quarantined) counts.quarantine++;
    if (m.software_blocked) counts.software++;
    if (r === "allow" || r === "contain") counts.clean++;
    const k = osKind(m.os); os[k] = (os[k] || 0) + 1;
  });
  const totalExt = sum(ms, (m) => m.extensions);
  const totalSw = sum(ms, (m) => m.software || 0);
  $("#m-kpis").innerHTML = [
    kpi({ key: "m-all", label: "Computers", value: ms.length, sub: Object.entries(os).map(([k, n]) => `${n} ${OS_LABEL[k]}`).join(" · ") || "none yet", iconName: "monitor", color: C.sky, filter: "all", on: state.mFilter === "all" }),
    kpi({ key: "m-act", label: "Need action", value: counts.action, sub: `${pct(counts.action, ms.length)}% of the fleet`, iconName: "flame", color: C.red, filter: "action", on: state.mFilter === "action" }),
    kpi({ key: "m-q", label: "With quarantine", value: counts.quarantine, sub: "run a quarantined build", iconName: "shield", color: C.amber, filter: "quarantine", on: state.mFilter === "quarantine" }),
    kpi({ key: "m-sw", label: "Blocked software", value: counts.software, sub: "a CVE hit an installed version", iconName: "bug", color: C.orange, filter: "software", on: state.mFilter === "software" }),
    kpi({ key: "m-avg", label: "Avg. extensions", value: ms.length ? Math.round(totalExt / ms.length) : 0, sub: `${ms.length ? Math.round(totalSw / ms.length) : 0} programs per computer`, iconName: "layers", color: C.violet }),
  ].join("");

  const seg = [["all", "All", ms.length], ["action", "Needs action", counts.action], ["quarantine", "Quarantine", counts.quarantine], ["software", "Blocked software", counts.software], ["clean", "Clean", counts.clean]];
  $("#m-seg").innerHTML = ms.length ? seg.map(([k, l, n]) => `<button type="button" data-mf="${k}" aria-pressed="${state.mFilter === k}">${l}<em>${n}</em></button>`).join("") : "";
  const osKeys = Object.keys(os);
  $("#m-os").innerHTML = osKeys.length > 1 ? [["", "Any OS"], ...osKeys.map((k) => [k, OS_LABEL[k]])].map(([k, l]) =>
    `<button type="button" data-mos="${k}" aria-pressed="${state.mOs === k}">${k ? ic(k) : ""}${l}${k ? `<em>${os[k]}</em>` : ""}</button>`).join("") : "";
  $$("#m-mode button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === state.mMode)));
  countUp($("#m-kpis"));
  renderMachineList();
}

function renderMachineList() {
  const el = $("#m-canvas");
  const ms = [...state.machines].sort((a, b) => a.hostname.localeCompare(b.hostname));
  if (state.mMode === "map") el.innerHTML = topology(ms);
  else if (state.mMode === "grid") el.innerHTML = machineGrid(ms);
  else el.innerHTML = machineRows(ms);

  const riskCount = {};
  ms.forEach((m) => { const r = riskOf(m); riskCount[r] = (riskCount[r] || 0) + 1; });
  $("#m-legend").innerHTML = ms.length ? RISK_ORDER.filter((r) => riskCount[r]).map((r) =>
    `<button type="button" data-mf="risk:${r}" aria-pressed="${state.mFilter === `risk:${r}`}" style="--c:${RISK[r].color}"><i></i>${RISK[r].label} <b>${riskCount[r]}</b></button>`).join("") : "";
}

function topology(ms) {
  const W = 760, H = 460, cx = W / 2, cy = H / 2;
  const n = ms.length;
  const K = n <= 10 ? 1 : n <= 26 ? 2 : n <= 56 ? 3 : 4;
  const radii = Array.from({ length: K }, (_, i) => {
    const t = K === 1 ? 1 : (i + 1) / K;
    return [130 + t * (W / 2 - 70 - 130), 95 + t * (H / 2 - 42 - 95)];
  });
  const perim = radii.map(([a, b]) => Math.PI * (3 * (a + b) - Math.sqrt((3 * a + b) * (a + 3 * b))));
  const totalP = sum(perim);
  let caps = perim.map((p) => Math.floor((p / totalP) * n));
  let left = n - sum(caps);
  for (let i = K - 1; left > 0; i = (i - 1 + K) % K, left--) caps[i]++;
  const base = n > 50 ? 6 : n > 24 ? 8 : 11;
  const nodes = [];
  let idx = 0;
  radii.forEach(([rx, ry], ring) => {
    const cnt = caps[ring];
    for (let j = 0; j < cnt; j++, idx++) {
      const a = -Math.PI / 2 + (j / cnt) * 2 * Math.PI + (ring % 2 ? Math.PI / cnt : 0);
      nodes.push({ m: ms[idx], x: cx + rx * Math.cos(a), y: cy + ry * Math.sin(a) });
    }
  });
  const orbits = radii.map(([rx, ry]) => `<ellipse class="orbit" cx="${cx}" cy="${cy}" rx="${rx}" ry="${ry}"/>`).join("");
  const edges = nodes.map(({ m, x, y }, i) => {
    const r = riskOf(m);
    const hot = r === "quarantine" || r === "block";
    const dim = machineMatches(m) ? "" : "style=\"opacity:.08\"";
    return `<line class="edge flow" x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" style="--c:${hot ? RISK[r].color : "rgba(109, 210, 193,.55)"};--d:-${(i * 0.37) % 1.6}s" ${dim}/>`;
  }).join("");
  const showLabels = n <= 18;
  const body = nodes.map(({ m, x, y }, i) => {
    const r = riskOf(m);
    const rad = base + Math.min(m.extensions || 0, 14) * (n > 24 ? 0.35 : 0.6);
    const sel = state.machine === m.machine_id;
    const alarm = r === "quarantine" || r === "block";
    const tip = `${m.hostname}\n${m.os}\n${RISK[r].label} · ${plural(m.extensions, "extension")} · ${plural(m.software ?? 0, "program")}${m.quarantined ? `\n${m.quarantined} quarantined` : ""}${m.software_blocked ? `\n${m.software_blocked} blocked software` : ""}\nLast report ${ago(m.collected_at)}`;
    return `<g class="node ${sel ? "sel" : ""} ${alarm ? "alarm" : ""} ${machineMatches(m) ? "" : "dim"}" data-machine="${esc(m.machine_id)}" transform="translate(${x.toFixed(1)} ${y.toFixed(1)})"
      style="--c:${RISK[r].color};--d:${(Math.min(i * 30, 1200) / 1000).toFixed(2)}s" data-tip="${esc(tip)}" role="option" aria-selected="${sel}" aria-label="${esc(m.hostname)}" tabindex="0">
      <circle class="halo" r="${rad}"/><circle class="sel-ring" r="${rad + 6}"/>
      <circle class="core" r="${rad}"/><circle class="dotc" r="${Math.max(2, rad * 0.32)}"/>
      ${showLabels ? `<text class="lbl-t" y="${rad + 15}">${esc(m.hostname)}</text>` : ""}</g>`;
  }).join("");
  const hubR = 34;
  return `<svg class="topo" viewBox="0 0 ${W} ${H}" role="img" aria-label="Network map of reporting computers">
    <defs>
      <radialGradient id="hubGlow"><stop offset="0" stop-color="rgba(109, 210, 193,.45)"/><stop offset="1" stop-color="rgba(109, 210, 193,0)"/></radialGradient>
      <linearGradient id="hubStroke" x1="0" x2="1"><stop offset="0" stop-color="${C.pink}"/><stop offset="1" stop-color="${C.blue}"/></linearGradient>
      <linearGradient id="sweepG" x1="0" x2="1" y1="0" y2="0"><stop offset="0" stop-color="rgba(109, 210, 193,0)"/><stop offset="1" stop-color="rgba(109, 210, 193,.18)"/></linearGradient>
    </defs>
    ${orbits}
    <g class="sweep" style="transform-origin:${cx}px ${cy}px"><path d="M${cx} ${cy} L${cx + W / 2} ${cy} A${W / 2} ${W / 2} 0 0 0 ${(cx + (W / 2) * Math.cos(-0.5)).toFixed(1)} ${(cy + (W / 2) * Math.sin(-0.5)).toFixed(1)} Z" fill="url(#sweepG)"/></g>
    ${edges}
    <circle class="hub-glow" cx="${cx}" cy="${cy}" r="${hubR * 2.6}"/>
    <circle class="hub-ring" cx="${cx}" cy="${cy}" r="${hubR}"/><circle class="hub-ring d2" cx="${cx}" cy="${cy}" r="${hubR}"/>
    <circle class="hub-core" cx="${cx}" cy="${cy}" r="${hubR}"/>
    <image href="img/logo.png" x="${cx - 24}" y="${cy - 25}" width="48" height="48"/>
    <text class="hub-t" x="${cx}" y="${cy + hubR + 16}">Blindspot server</text>
    ${body}
  </svg>${n ? "" : `<div class="topo-empty">Waiting for the first agent to report. <a href="#add" data-goto="add">Add a computer</a></div>`}`;
}

function machineGrid(ms) {
  const list = ms.filter(machineMatches);
  if (!ms.length) return `<p class="empty">No computer has reported yet. <a href="#add" data-goto="add">Add a computer</a></p>`;
  if (!list.length) return `<p class="empty">No computer matches these filters.</p>`;
  return `<div class="mgrid">${list.map((m, i) => {
    const r = riskOf(m);
    const x = state.meta.get(m.hostname);
    const kind = osKind(m.os);
    return `<button class="mtile" type="button" role="option" data-machine="${esc(m.machine_id)}" aria-selected="${state.machine === m.machine_id}" style="--c:${RISK[r].color};--d:${Math.min(i * 30, 900)}ms">
      <div class="mt-top">${ic(kind)}<span>${esc(OS_LABEL[kind])}</span><span class="risk">${RISK[r].label}</span></div>
      <div class="mt-name" title="${esc(m.hostname)}">${esc(m.hostname)}</div>
      <div class="mt-stats">
        <span><b>${esc(m.extensions)}</b>extensions</span>
        <span><b class="${m.high_risk ? "bad" : ""}">${esc(m.high_risk)}</b>high risk</span>
        <span><b class="${m.software_blocked ? "bad" : ""}">${esc(m.software ?? 0)}</b>programs</span>
      </div>
      ${x ? stackBar(decParts(x.dec)) : ""}
      <div class="mt-foot">${esc(m.os)} · ${esc(ago(m.collected_at))}</div>
    </button>`;
  }).join("")}</div>`;
}

function machineRows(ms) {
  const list = ms.filter(machineMatches);
  if (!ms.length) return `<p class="empty">No computer has reported yet. <a href="#add" data-goto="add">Add a computer</a></p>`;
  if (!list.length) return `<p class="empty">No computer matches these filters.</p>`;
  return `<div class="mlist">${list.map((m) => {
    const r = riskOf(m);
    const flags = [
      m.quarantined ? tag("quarantine", `${m.quarantined} quarantined`) : "",
      m.high_risk ? tag("block", `${m.high_risk} to block`) : "",
      m.software_blocked ? tag("blocked", `${m.software_blocked} software`) : "",
    ].join("");
    return `<button role="option" type="button" data-machine="${esc(m.machine_id)}" aria-selected="${state.machine === m.machine_id}" style="--c:${RISK[r].color}">
      <span class="dot"></span><span class="name">${esc(m.hostname)}</span><span class="flags">${flags || `<span class="tag allow">${RISK[r].label}</span>`}</span>
      <span class="sub">${esc(m.os)}, ${plural(m.extensions, "extension")}, ${plural(m.software ?? 0, "program")} · ${esc(ago(m.collected_at))}</span></button>`;
  }).join("")}</div>`;
}

function markSelectedMachine() {
  $$("#m-canvas [data-machine]").forEach((n) => {
    const on = n.dataset.machine === state.machine;
    n.setAttribute("aria-selected", String(on));
    n.classList.toggle("sel", on);
  });
}

async function renderMachine(id) {
  state.machine = id;
  markSelectedMachine();
  const m = await Api.machine(id);
  const el = $("#machine-detail");
  if (!m) { el.innerHTML = `<p class="empty">This machine has not reported.</p>`; return; }
  state.machine = m.machine_id;
  markSelectedMachine();
  const row = state.machines.find((x) => x.machine_id === m.machine_id) || { quarantined: 0, software_blocked: 0, extensions: m.extensions.length, high_risk: 0 };
  const r = riskOf({ ...row, hostname: m.hostname });
  const kind = osKind(m.os);
  const dec = {};
  m.extensions.forEach((e) => { dec[e.recommendation] = (dec[e.recommendation] || 0) + 1; });
  const atRisk = m.extensions.filter((e) => e.severity === "High" || e.severity === "Critical").length;
  const swBlocked = m.software.filter((s) => s.status === "blocked").length;
  const maxExt = Math.max(1, ...state.machines.map((x) => x.extensions));
  const maxSw = Math.max(1, ...state.machines.map((x) => x.software || 0));
  const systems = [...new Set(m.extensions.flatMap((e) => e.exposure || []))];
  const swParts = ["blocked", "review", "unreviewed", "allowed"].map((k) => ({ key: k, label: SW_STATUS[k], value: m.software.filter((s) => s.status === k).length, color: SW_COLOR[k] }));

  const exts = [...m.extensions].sort((a, b) => b.score - a.score).map((e) => `
    <tr data-key="${esc(e.id)}" class="${e.quarantined ? "taped" : ""}">
      <td>${ring(e.score, 100, sevColor(e.severity), { size: 36, stroke: 3 })}</td>
      <td><div class="name">${esc(e.name)} ${e.ai ? tag("ai", "AI") : ""}</div><div class="sub">${esc(e.version)}, ${esc(e.browser)} / ${esc(e.profile)}</div></td>
      <td>${tag(e.recommendation)}</td></tr>`).join("");
  const sw = [...m.software].sort((a, b) => (b.cvss_max || 0) - (a.cvss_max || 0)).map((s) => {
    const b = bandOf(s.cvss_max);
    return `<tr data-sw="${esc(s.name)}|${esc(s.version)}">
      <td><b style="font:700 15px var(--display);color:${b.color}">${s.cvss_max ? esc(s.cvss_max.toFixed(1)) : "–"}</b></td>
      <td><div class="name">${esc(s.name)}</div><div class="sub">${esc(s.version)}${s.publisher ? `, ${esc(s.publisher)}` : ""}</div></td>
      <td>${tag(s.status)}</td></tr>`;
  }).join("");
  updateDetail(el, id, `
    <div class="d-head">
      <div class="d-title"><div class="d-ic" style="--accent:${RISK[r].color}">${ic(kind)}</div>
        <div><h2>${esc(m.hostname)}</h2><div class="ver">${esc(m.os)} · last report ${esc(time(m.collected_at)) || "unknown"} (${esc(ago(m.collected_at))})</div></div></div>
      <span class="risk-pill" style="--c:${RISK[r].color}">${RISK[r].label}</span>
    </div>
    <div class="ring-row">
      <div>${ring(m.extensions.length, maxExt, C.violet, { size: 54, stroke: 5 })}<span>extensions</span></div>
      <div>${ring(atRisk, Math.max(1, m.extensions.length), atRisk ? C.red : C.green, { size: 54, stroke: 5 })}<span>high / critical</span></div>
      <div>${ring(m.software.length, maxSw, C.blue, { size: 54, stroke: 5 })}<span>programs</span></div>
      <div>${ring(swBlocked, Math.max(1, m.software.length), swBlocked ? C.red : C.green, { size: 54, stroke: 5 })}<span>blocked</span></div>
    </div>
    <details><summary>Decision breakdown</summary>
    ${m.extensions.length ? `<h3 class="block-title">Extension decisions</h3>${stackBar(decParts(dec))}${stackLegend(decParts(dec))}` : ""}
    ${m.software.length ? `<h3 class="block-title">Software status</h3>${stackBar(swParts)}${stackLegend(swParts)}` : ""}
    </details>
    ${systems.length ? `<h3 class="block-title">Critical systems reachable from here</h3><div class="chips">${systems.map((s) => `<span class="chip sys">${esc(s)}</span>`).join("")}</div>` : ""}
    <details><summary>Browser extensions (${m.extensions.length})</summary>
    <table class="mini-table"><tbody>${exts || `<tr><td class="quiet">No extensions found.</td></tr>`}</tbody></table>
    </details>
    <details><summary>Installed software (${m.software.length})</summary>
    <table class="mini-table"><tbody>${sw || `<tr><td class="quiet">No software inventory. Run the agent without --no-software.</td></tr>`}</tbody></table>
    </details>`);
  $$("tr[data-key]", el).forEach((tr) => tr.addEventListener("click", () => { go("extensions"); renderExtDetail(tr.dataset.key); }));
  $$("tr[data-sw]", el).forEach((tr) => tr.addEventListener("click", () => { go("software"); renderSwDetail(tr.dataset.sw); }));
}

// ------------------------------------------------------------------ software

function swKey(s) { return `${s.name}|${s.version}`; }

function swMatches(s) {
  const text = $("#sw-filter").value.trim().toLowerCase();
  const q = state.swQuick;
  return (!state.swStatus || s.status === state.swStatus)
    && (!state.swBand || bandOf(s.cvss_max).key === state.swBand)
    && (!q || (q === "cves" && s.vulnerability_count) || (q === "kev" && s.kev) || (q === "remote" && s.remote_access) || (q === "blocked" && s.status === "blocked"))
    && (!text || `${s.name} ${s.publisher}`.toLowerCase().includes(text));
}

function renderSoftwareView() {
  const sw = state.software;
  const n = (f) => sw.filter(f).length;
  $("#sw-kpis").innerHTML = [
    kpi({ key: "s-all", label: "Programs", value: sw.length, sub: `on ${plural(state.machines.length, "computer")}`, iconName: "package", color: C.sky, filter: "", on: !state.swQuick }),
    kpi({ key: "s-cve", label: "With known CVEs", value: n((s) => s.vulnerability_count), sub: `${sum(sw, (s) => s.vulnerability_count || 0)} CVEs in total`, iconName: "bug", color: C.orange, filter: "cves", on: state.swQuick === "cves" }),
    kpi({ key: "s-blk", label: "Blocked", value: n((s) => s.status === "blocked"), sub: "until the fix is installed", iconName: "lock", color: C.red, filter: "blocked", on: state.swQuick === "blocked" }),
    kpi({ key: "s-kev", label: "Known exploited", value: n((s) => s.kev), sub: "listed in CISA KEV", iconName: "flame", color: C.amber, filter: "kev", on: state.swQuick === "kev" }),
    kpi({ key: "s-ra", label: "Remote access", value: n((s) => s.remote_access), sub: "MITRE ATT&CK T1219", iconName: "remote", color: C.violet, filter: "remote", on: state.swQuick === "remote" }),
  ].join("");
  countUp($("#sw-kpis"));

  const bands = BANDS.map((b) => ({ ...b, n: sw.filter((s) => bandOf(s.cvss_max).key === b.key).length }));
  const maxN = Math.max(1, ...bands.map((b) => b.n));
  $("#sw-hist").className = `hist ${state.swBand ? "filtered" : ""}`;
  $("#sw-hist").innerHTML = bands.map((b, i) => `<button type="button" data-band="${b.key}" class="${state.swBand === b.key ? "on" : ""}" data-tip="${b.label}: ${b.n} ${b.n === 1 ? "program" : "programs"}">
      <b>${b.n}</b><span class="bar-area"><span class="col" style="height:${(b.n / maxN) * 100}%;--c:${b.color};animation-delay:${i * 70}ms"></span></span><span>${b.label}</span></button>`).join("");

  const counts = {};
  sw.forEach((s) => { counts[s.status] = (counts[s.status] || 0) + 1; });
  $("#sw-seg").innerHTML = [["", "All", sw.length, null], ...["blocked", "review", "unreviewed", "allowed"].map((k) => [k, SW_STATUS[k], counts[k] || 0, SW_COLOR[k]])]
    .filter(([k, , c]) => !k || c || state.swStatus === k)
    .map(([k, l, c, col]) => `<button type="button" data-sws="${k}" aria-pressed="${state.swStatus === k}" ${col ? `style="--c:${col}"` : ""}>${col ? '<i class="dot"></i>' : ""}${l}<em>${c}</em></button>`).join("");
  renderSwRows();
}

function renderSwRows() {
  const { key, dir } = state.swSort;
  const fleet = Math.max(1, state.machines.length);
  const rows = state.software.filter(swMatches).sort((a, b) => {
    if (key === "name") return dir * a.name.localeCompare(b.name);
    if (key === "machines") return dir * (a.machines - b.machines);
    return dir * ((a.cvss_max || 0) - (b.cvss_max || 0)) || (b.status === "blocked") - (a.status === "blocked");
  });
  $$("#view-software th[data-ssort]").forEach((th) => {
    th.classList.toggle("sorted", th.dataset.ssort === key);
    th.classList.toggle("asc", th.dataset.ssort === key && dir === 1);
  });
  $("#sw-rows").innerHTML = rows.map((s, i) => {
    const b = bandOf(s.cvss_max);
    return `
    <tr data-key="${esc(swKey(s))}" style="--i:${Math.min(i, 30)}" class="${state.sw === swKey(s) ? "on" : ""}">
      <td><div class="cvss"><b style="color:${b.color}">${s.cvss_max ? esc(s.cvss_max.toFixed(1)) : "–"}</b>
        <span class="meter thin"><i style="width:${(s.cvss_max || 0) * 10}%;background:${b.color};color:${b.color}"></i></span></div></td>
      <td><div class="name">${esc(s.name)} ${s.kev ? tag("kev", "KEV") : ""} ${s.remote_access ? tag("ra", "Remote access") : ""}</div>
        <div class="sub"><span class="vpill">${esc(s.version)}</span> ${s.publisher ? esc(s.publisher) : ""}</div></td>
      <td>${tag(s.status)}${s.vulnerability_count ? `<div class="sub" style="margin-top:4px">${plural(s.vulnerability_count, "CVE")}${s.fixes_all ? `, update to ${esc(s.fixes_all)}` : ""}</div>` : ""}</td>
      <td><div class="mcount" data-tip="${esc((s.hostnames || []).join("\n"))}"><b>${esc(s.machines)}</b><span class="meter thin"><i style="width:${pct(s.machines, fleet)}%;background:${C.violet};color:${C.violet}"></i></span></div></td></tr>`;
  }).join("") || (state.software.length ? `<tr><td colspan="4" class="empty">No software matches these filters.</td></tr>`
    : `<tr><td colspan="4" class="empty">No software inventory yet. Agents send it with every report.</td></tr>`);
}

function renderSwDetail(key) {
  state.sw = key;
  renderSwRows();
  const s = state.software.find((x) => swKey(x) === key);
  const el = $("#sw-detail");
  if (!s) { el.innerHTML = `<p class="empty">Pick a program to see its vulnerabilities and decision.</p>`; return; }
  const band = bandOf(s.cvss_max);
  const vulns = s.vulnerabilities.map((v) => {
    const vb = bandOf(v.cvss);
    return `
    <li style="--c:${vb.color}">
      <div class="v-top"><a href="https://nvd.nist.gov/vuln/detail/${esc(v.cve)}" target="_blank" rel="noopener">${esc(v.cve)}</a>
        ${v.kev ? tag("kev", "Known exploited") : ""} <span class="ssvc ${esc(v.decision)}">SSVC ${esc(v.decision)}</span>
        <span class="v-score">${esc(v.cvss)}</span></div>
      <span>${esc(v.title)}</span>
      <span class="meter thin"><i style="width:${(v.cvss || 0) * 10}%;background:${vb.color};color:${vb.color}"></i></span>
      <div class="v-meta"><span>${v.fixed ? `Fixed in <b>${esc(v.fixed)}</b>` : "No fixed version listed"}</span><span>·</span>
        <span>Affected: ${esc(v.affected || "")}</span><span>·</span><span>Source: ${v.source === "nvd" ? "NVD" : "Blindspot advisory"}</span></div>
      <code>${esc(v.vector)}</code></li>`;
  }).join("");
  const verdictCls = { blocked: "block", review: "review", allowed: "allow", unreviewed: "" }[s.status];
  updateDetail(el, key, `
    <div class="d-head">
      <div class="d-title"><div class="d-ic" style="--accent:${SW_COLOR[s.status]}">${ic(s.remote_access ? "remote" : "package")}</div>
        <div><h2>${esc(s.name)}</h2><div class="ver">Version ${esc(s.version)}${s.publisher ? `, ${esc(s.publisher)}` : ""}</div></div></div>
      ${tag(s.status)}
    </div>
    <div class="cvss-hero">
      ${gauge((s.cvss_max || 0) * 10, { label: `<span style="color:${band.color}">${s.cvss_max ? esc(s.cvss_max.toFixed(1)) : "0.0"}</span>`, sub: s.cvss_max ? `CVSS · ${band.label}` : "no known CVE" })}
      <div class="gauge-stats" style="grid-template-columns:1fr 1fr;margin:0">
        <div><b>${esc(s.vulnerability_count || 0)}</b><span>known CVEs</span></div>
        <div><b>${esc(s.decision || "–")}</b><span>SSVC decision</span></div>
        <div><b>${esc(s.machines)}</b><span>${s.machines === 1 ? "computer" : "computers"}</span></div>
        <div><b>${esc(s.fixes_all || "–")}</b><span>fixes everything</span></div>
      </div>
    </div>
    <p class="verdict ${verdictCls}">${esc(s.reasons.join(". "))}.</p>
    <div class="gactions" style="margin-top:12px">
      ${s.approved
        ? `<button class="btn ghost" id="sw-unapprove" type="button">Remove ${esc(s.catalog_name)} from the approved list</button>`
        : `<button class="btn primary" id="sw-approve" type="button">${ic("check")} Approve this version</button>`}
    </div>
    <details><summary>Known vulnerabilities in this version${s.vulnerability_count ? ` (${esc(s.vulnerability_count)})` : ""}</summary>
    <p class="small quiet" style="margin-top:0">${s.tracked && s.tracked.length
      ? `Checked against NVD as ${esc(s.tracked.join(", "))}, with CISA KEV for active exploitation.`
      : "Not on the NVD watch list, so only Blindspot's built-in advisories apply. Add it to fixtures/software_watchlist.json."}</p>
    <ul class="reasons vulns">${vulns || `<li class="quiet">None known for this version.</li>`}</ul>
    ${s.vulnerability_count > s.vulnerabilities.length ? `<p class="small quiet">Showing the ${s.vulnerabilities.length} most urgent.</p>` : ""}
    </details>
    <details><summary>How this is decided</summary>
      <p class="small">Severity is the CVSS v3.1 base score from NVD. Exploitation comes from the CISA Known Exploited Vulnerabilities
        catalog. The decision follows CISA SSVC: Act, Attend, Track* or Track. Versions at
        <b>${esc((state.guard && state.guard.block_at_decision) || "Attend")}</b> or above are blocked until the fixed version is installed.
        Remote access tools outside the catalog need review (MITRE ATT&CK T1219).</p>
    </details>
    <h3 class="block-title">Installed on</h3>
    <div class="chips">${(s.hostnames || []).map((h) => `<button class="chip machine-chip" data-machine="${esc(h)}" type="button"><b>${esc(h)}</b></button>`).join("")}</div>`);
  $$("[data-machine]", el).forEach((b) => b.addEventListener("click", () => { go("machines"); renderMachine(b.dataset.machine); }));
  const approve = $("#sw-approve");
  if (approve) approve.addEventListener("click", async () => {
    try {
      const entry = await Api.approveSoftware(s.name, s.version, s.publisher);
      toast(`${entry.name} ${entry.approved_version} approved. Blindspot blocks it by itself if a CVE hits this version later.`);
      await refresh();
      state.sw = state.software.some((x) => swKey(x) === key) ? key : null;
      if (state.sw) renderSwDetail(key);
    } catch (err) { toast(err.message); }
  });
  const unapprove = $("#sw-unapprove");
  if (unapprove) unapprove.addEventListener("click", async () => {
    try { await Api.unapproveSoftware(s.catalog_name); toast(`${s.catalog_name} removed from the approved list.`); await refresh(); } catch (err) { toast(err.message); }
  });
}

// ------------------------------------------------------------------ guard

function renderGuard() {
  const g = state.guard;
  if (!g) return;
  const live = true;
  const pinned = g.extensions.filter((e) => e.state === "pinned").length;
  const quarantined = g.extensions.filter((e) => e.state === "quarantined").length;
  const loose = g.extensions.filter((e) => e.state === "not pinned");
  const catBlocked = g.catalog.filter((c) => c.state === "blocked").length;
  $("#g-kpis").innerHTML = [
    kpi({ key: "g-p", label: "Pinned builds", value: pinned, sub: "trusted by code hash", iconName: "pin", color: C.green }),
    kpi({ key: "g-q", label: "Quarantined", value: quarantined, sub: quarantined ? "waiting for review" : "no drift detected", iconName: "alert", color: C.amber }),
    kpi({ key: "g-l", label: "Not pinned", value: loose.length, sub: "any future version trusted", iconName: "eye", color: C.slate }),
    kpi({ key: "g-c", label: "Software catalog", value: g.catalog.length, sub: `${catBlocked} with a blocked version`, iconName: "package", color: C.blue }),
    kpi({ key: "g-e", label: "Events", value: g.events.length, sub: "in the activity log", iconName: "activity", color: C.violet }),
  ].join("");
  countUp($("#g-kpis"));

  $("#g-ext-note").textContent = `${pinned} pinned, ${quarantined} quarantined`;
  const HOW = { "approved list (first seen)": "from the approved list", "automatic: benign update": "update approved automatically", "first seen": "watched since its first report" };
  const tracked = g.extensions.filter((e) => e.state !== "not pinned");
  $("#g-ext").innerHTML = tracked.map((e) => {
    const q = e.quarantine[0];
    const pills = e.installed.map((v) => `<span class="ver-pill ${v.quarantined ? "bad" : e.approved_versions.includes(v.version) ? "good" : ""}">${esc(v.version)} on ${plural(v.machines, "machine")}</span>`).join("");
    const how = HOW[e.approved_how] || e.approved_how || "";
    const base = `Pinned to ${esc(e.baseline_version)} (code hash <code>${esc(e.baseline_hash || "n/a")}</code>)${how ? `, ${esc(how)}` : ""}.`;
    const actions = e.state === "quarantined"
      ? `<button class="btn primary" data-approve="${esc(e.id)}" data-version="${esc(q.version)}" ${live ? "" : "disabled"} type="button">Approve ${esc(q.version)} after review</button>
         <button class="btn ghost" data-open="${esc(e.id)}" type="button">Open extension</button>`
      : "";
    return `<div class="gitem ${e.state === "quarantined" ? "taped" : ""}">
      <div><div class="name">${esc(e.name)} ${e.severity ? `<span class="sub sev-${esc(e.severity)}">${esc(e.severity)}</span>` : ""}</div><div class="sub">${base}</div></div>
      <div>${tag(e.state)}</div>
      <div class="versions">${pills}</div>
      ${q ? `<ul class="diff">${q.reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
      ${actions ? `<div class="gactions">${actions}</div>` : ""}
    </div>`;
  }).join("") + (loose.length ? `
    <div class="loose"><p class="small quiet">Not pinned: any future version with these IDs would be trusted.</p>
      <table><tbody>${loose.map((e) => `<tr><td><span class="name" style="display:inline">${esc(e.name)}</span> <span class="sub">${esc(e.installed.map((v) => v.version).join(", "))}</span></td>
        <td class="right">${e.severity ? `<span class="sub sev-${esc(e.severity)}">${esc(e.severity)}</span>` : ""}</td>
        <td class="right"><button class="btn ghost small" data-approve="${esc(e.id)}" ${live ? "" : "disabled"} type="button">Pin build</button></td></tr>`).join("")}</tbody></table></div>` : "")
    || `<p class="empty">No extension reported yet.</p>`;

  $("#g-sw").innerHTML = g.catalog.map((c) => {
    const pills = c.installed.map((v) => `<span class="ver-pill ${v.status === "blocked" ? "bad" : "good"}" data-tip="${esc(v.reasons.join(". "))}">${esc(v.version)} on ${plural(v.machines, "machine")}</span>`).join("");
    const blockedReasons = [...new Set(c.installed.filter((v) => v.status === "blocked").map((v) => v.reasons[0]))];
    return `<div class="gitem">
      <div><div class="name">${esc(c.name)}</div>
        <div class="sub">Approved ${esc(c.approved_version)} by ${esc(c.approved_by || "IT")}${c.approved_at ? ` on ${esc(c.approved_at)}` : ""}. Installs allowed from <b>${esc(c.allowed_from)}</b>.</div></div>
      <div>${tag(c.state === "blocked" ? "blocked" : "allowed", c.state === "blocked" ? "Version blocked" : "Allowed")}</div>
      <div class="versions">${pills || `<span class="quiet small">Not installed anywhere.</span>`}</div>
      ${blockedReasons.length ? `<ul class="diff">${blockedReasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
    </div>`;
  }).join("") + (g.unapproved.length ? `<div class="gitem"><div><div class="name">Outside the catalog</div>
      <div class="sub">${g.unapproved.map((s) => `${esc(s.name)} ${esc(s.version)}: ${esc(s.reasons[0])}`).join("<br>")}</div></div></div>` : "")
    || `<p class="empty">The approved catalog is empty. Approve a program on the Software page.</p>`;

  $("#g-log").innerHTML = logItems(g.events);

  $$("#view-guard [data-approve]").forEach((b) => b.addEventListener("click", async () => {
    try {
      const res = await Api.approve(b.dataset.approve, b.dataset.version);
      toast(`Approved version ${res.version}${res.released ? " and released from quarantine" : ""}.`);
      await refresh();
    } catch (err) { toast(err.message); }
  }));
  $$("#view-guard [data-open]").forEach((b) => b.addEventListener("click", () => { go("extensions"); renderExtDetail(b.dataset.open); }));
}

// ------------------------------------------------------------------ critical systems

async function renderCrown() {
  const data = await Api.exposure();
  state.exposure = data;
  $("#crown-list").innerHTML = data.map((c, i) => {
    const hot = c.extensions.some((e) => e.level === "high" || e.recommendation === "quarantine");
    const dec = {};
    c.extensions.forEach((e) => { dec[e.recommendation] = (dec[e.recommendation] || 0) + e.installs; });
    const exts = [...c.extensions].sort((a, b) => b.score - a.score).map((e) =>
      `<span class="chip ${e.level === "high" ? "hot" : ""}" data-tip="${esc(e.name)} · score ${esc(e.score)}\n${esc(e.machines.join("\n"))}">${esc(e.name)} ${tag(e.recommendation)}</span>`).join("");
    return `<div class="card crown-card ${hot ? "hot" : ""}" style="--d:${i * 60}ms">
      <div><h3>${esc(c.system)}</h3><code class="quiet">${esc(c.hosts.join(", "))}</code></div>
      <div class="crown-nums">
        <div><b data-count="${c.extension_count}" data-ck="cj-e-${esc(c.system)}">0</b><span>${c.extension_count === 1 ? "extension" : "extensions"} can reach it</span></div>
        <div><b data-count="${c.machine_count}" data-ck="cj-m-${esc(c.system)}">0</b><span>${c.machine_count === 1 ? "machine" : "machines"}</span></div>
      </div>
      ${c.extension_count ? `${stackBar(decParts(dec))}` : ""}
      <div class="chips">${exts || `<span class="quiet">No extension can reach it.</span>`}</div>
    </div>`;
  }).join("") || `<div class="card"><p class="empty">No critical systems are configured in fixtures/crown_jewels.json.</p></div>`;
  countUp($("#crown-list"));
}

// ------------------------------------------------------------------ add a computer

async function renderAdd() {
  const input = $("#server-url");
  if (!input.dataset.ready) {
    input.dataset.ready = "1";
    let suggested = [];
    try { suggested = (await Api.serverInfo()).suggested || []; } catch { /* older server */ }
    const local = ["localhost", "127.0.0.1", "::1"].includes(location.hostname);
    input.value = local && suggested.length ? suggested[0] : location.origin;
    const options = [...new Set([location.origin, ...suggested])];
    $("#server-suggest").innerHTML = options.map((o) => `<button class="chip" type="button" data-url="${esc(o)}">${esc(o)}</button>`).join("");
    $$("#server-suggest button").forEach((b) => b.addEventListener("click", () => { input.value = b.dataset.url; updateAgentLinks(); }));
    input.addEventListener("input", updateAgentLinks);
    updateAgentLinks();
  }
  $("#arrivals").innerHTML = [...state.machines].sort((a, b) => String(b.collected_at).localeCompare(String(a.collected_at))).map((m, i) => {
    const r = riskOf(m);
    return `<li style="--c:${RISK[r].color};animation-delay:${Math.min(i * 40, 500)}ms"><span class="a-ic">${ic(osKind(m.os))}</span>
      <span class="a-main"><b>${esc(m.hostname)}</b><br><span class="sub">${esc(m.os)}</span></span>
      <span class="a-side sub">${plural(m.extensions, "extension")}<br>${esc(time(m.collected_at))} · ${esc(ago(m.collected_at))}</span></li>`;
  }).join("") || `<li class="quiet">Nobody yet.</li>`;
}

function updateAgentLinks() {
  const url = $("#server-url").value.trim().replace(/\/+$/, "");
  $("#agent-dl").href = Api.agentZipUrl(url);
  $("#cmd-line").textContent = `python -m blindspot agent --server ${url} --every 10`;
}

// ------------------------------------------------------------------ live vulnerability data

let feedTimer = null;

function renderFeeds(f) {
  if (!f) return;
  const pills = [];
  if (f.running) pills.push(`<span class="fs run"><b>Checking ${esc(f.progress || "")}</b></span>`);
  pills.push(f.kev.fetched_at
    ? `<span class="fs ok">CISA KEV <b>${esc(f.kev.count.toLocaleString())}</b> exploited CVEs · ${esc(time(f.kev.fetched_at))}</span>`
    : `<span class="fs warn">CISA KEV not fetched yet</span>`);
  pills.push(f.nvd.tracked.length
    ? `<span class="fs ok" data-tip="${esc(f.nvd.tracked.join("\n"))}">NVD <b>${f.nvd.tracked.length}</b> installed ${f.nvd.tracked.length === 1 ? "product" : "products"} tracked</span>`
    : `<span class="fs warn">NVD: none of the installed programs is on the watch list yet</span>`);
  if (f.checked_at) pills.push(`<span class="fs">Last full check <b>${esc(time(f.checked_at))}</b></span>`);
  pills.push(f.api_key ? `<span class="fs ok">NVD API key set</span>` : `<span class="fs">No NVD API key: 6 s per request</span>`);
  if (f.error) pills.push(`<span class="fs err">${esc(f.error)}</span>`);
  $("#feed-status").innerHTML = pills.join("");
  $(".intel-ic").classList.toggle("busy", Boolean(f.running));
  ["#feed-refresh", "#sync-btn"].forEach((id) => {
    const b = $(id);
    if (b) { b.disabled = f.running; b.textContent = f.running ? "Checking…" : "Check for new CVEs now"; }
  });
}

async function watchFeeds() {
  clearTimeout(feedTimer);
  try {
    const f = await Api.feeds();
    renderFeeds(f);
    if (f.running) { feedTimer = setTimeout(async () => { await watchFeeds(); }, 3000); state.feedsWasRunning = true; return; }
    if (state.feedsWasRunning) { state.feedsWasRunning = false; await refresh(); toast("Vulnerability check finished."); }
  } catch { /* server gone; the poller reports it */ }
}

async function checkFeedsNow() {
  try {
    await Api.syncFeed().catch(() => null);  // curated advisories shipped with Blindspot
    await Api.refreshFeeds();
    state.feedsWasRunning = true;
    toast("Checking NVD and CISA KEV. Results appear here when it finishes.");
    watchFeeds();
  } catch (err) { toast(err.message); }
}

// ------------------------------------------------------------------ alerts

const tg = { chat: null };

async function renderAlerts() {
  let cfg;
  try { cfg = await Api.alerts(); } catch { return; }
  const t = cfg.telegram;
  $("#n-alerts").textContent = t.configured ? "on" : "";
  $("#tg-status").innerHTML = t.configured
    ? `<div class="status-line"><span class="dot on"></span><div><h3>Sending to ${esc(t.chat_name || t.chat_id)}</h3>
        <div class="sub">Bot token ${esc(t.token)}. Chat ${esc(t.chat_id)}.</div></div></div>
       <div class="gactions" style="margin-top:12px"><button class="btn ghost" id="tg-test" type="button">Send a test message</button>
       <button class="btn ghost" id="tg-off" type="button">Turn off</button></div>`
    : `<div class="status-line"><span class="dot"></span><div><h3>Not set up</h3>
        <div class="sub">Follow the four steps. It takes about two minutes.</div></div></div>`;
  $$("#view-alerts .check input").forEach((box) => { box.checked = cfg.kinds.includes(box.value); });
  if (t.configured && !tg.chat) tg.chat = { chat_id: t.chat_id, name: t.chat_name };
  const test = $("#tg-test");
  if (test) test.addEventListener("click", sendTest);
  const off = $("#tg-off");
  if (off) off.addEventListener("click", async () => {
    try { await Api.disableTelegram(); tg.chat = null; toast("Telegram alerts turned off."); renderAlerts(); } catch (err) { toast(err.message); }
  });
}

async function sendTest() {
  try { await Api.testAlert(); toast("Test message sent. Check Telegram."); } catch (err) { toast(err.message); }
}

function bindAlerts() {
  $("#tg-find").addEventListener("click", async () => {
    const token = $("#tg-token").value.trim();
    try {
      const chats = await Api.findChats(token);
      if (!chats.length) {
        $("#tg-chats").innerHTML = `<span class="quiet small">No messages yet. Send your bot a message in Telegram, then press Find my chat again.</span>`;
        return;
      }
      $("#tg-chats").innerHTML = chats.map((c) => `<button class="chip" type="button" data-chat="${esc(c.chat_id)}" data-name="${esc(c.name)}">${esc(c.name)}</button>`).join("");
      const pick = (b) => {
        $$("#tg-chats .chip").forEach((x) => x.classList.toggle("picked", x === b));
        tg.chat = { chat_id: b.dataset.chat, name: b.dataset.name };
      };
      $$("#tg-chats .chip").forEach((b) => b.addEventListener("click", () => pick(b)));
      pick($("#tg-chats .chip"));
    } catch (err) { toast(err.message); }
  });
  $("#tg-save").addEventListener("click", async () => {
    const token = $("#tg-token").value.trim();
    if (!tg.chat) { toast("Press Find my chat first, after sending your bot a message."); return; }
    const kinds = $$("#view-alerts .check input").filter((b) => b.checked).map((b) => b.value);
    const dashboard = ($("#server-url").value || location.origin).trim().replace(/\/+$/, "");
    try {
      await Api.saveTelegram({ ...(token ? { token } : {}), chat_id: tg.chat.chat_id, chat_name: tg.chat.name, kinds, dashboard_url: dashboard });
      $("#tg-token").value = "";
      await renderAlerts();
      await sendTest();
    } catch (err) { toast(err.message); }
  });
  $$("#view-alerts .check input").forEach((box) => box.addEventListener("change", async () => {
    const kinds = $$("#view-alerts .check input").filter((b) => b.checked).map((b) => b.value);
    try { await Api.saveTelegram({ kinds }); } catch (err) { toast(err.message); }
  }));
}

// ------------------------------------------------------------------ command palette

const palette = { items: [], sel: 0 };

function openPalette() {
  $("#palette").classList.remove("hidden");
  const input = $("#palette-input");
  input.value = "";
  buildPalette("");
  setTimeout(() => input.focus(), 10);
}

function closePalette() { $("#palette").classList.add("hidden"); }

function buildPalette(q) {
  const ql = q.trim().toLowerCase();
  const all = [
    ...VIEWS.map((v) => ({ type: "Pages", label: VIEW_META[v][0], sub: VIEW_META[v][1], icon: VIEW_ICON[v], color: C.violet, run: () => go(v) })),
    ...[...state.extensions].sort((a, b) => b.score - a.score).map((e) => ({ type: "Extensions", label: e.name, sub: `${e.score} · ${e.severity} · ${DECISION[e.recommendation]} · ${plural(e.installs, "machine")}`, icon: "puzzle", color: sevColor(e.severity), run: () => { go("extensions"); renderExtDetail(e.id); } })),
    ...state.machines.map((m) => ({ type: "Machines", label: m.hostname, sub: `${m.os} · ${RISK[riskOf(m)].label}`, icon: osKind(m.os), color: RISK[riskOf(m)].color, run: () => { go("machines"); renderMachine(m.machine_id); } })),
    ...state.software.map((s) => ({ type: "Software", label: s.name, sub: `${s.version} · ${SW_STATUS[s.status]}${s.cvss_max ? ` · CVSS ${s.cvss_max.toFixed(1)}` : ""}`, icon: "package", color: SW_COLOR[s.status], run: () => { go("software"); renderSwDetail(swKey(s)); } })),
  ];
  const hits = ql ? all.filter((i) => `${i.label} ${i.sub} ${i.type}`.toLowerCase().includes(ql)) : all.filter((i) => i.type === "Pages" || i.type === "Extensions").slice(0, 14);
  palette.items = hits.slice(0, 50);
  palette.sel = 0;
  drawPalette();
}

function drawPalette() {
  let last = "";
  $("#palette-list").innerHTML = palette.items.map((it, i) => {
    const head = it.type !== last ? `<div class="p-group">${esc(it.type)}</div>` : "";
    last = it.type;
    return `${head}<button class="p-item ${i === palette.sel ? "on" : ""}" type="button" data-pi="${i}" style="--c:${it.color}" role="option" aria-selected="${i === palette.sel}">
      <span class="p-ic">${ic(it.icon)}</span><span><b>${esc(it.label)}</b><small>${esc(it.sub)}</small></span><span class="p-type">${i === palette.sel ? "↵" : ""}</span></button>`;
  }).join("") || `<div class="p-none">Nothing matches. Try a hostname, an extension or a program.</div>`;
  const on = $(".p-item.on");
  if (on) on.scrollIntoView({ block: "nearest" });
}

function runPalette(i) {
  const it = palette.items[i];
  if (!it) return;
  closePalette();
  it.run();
}

// ------------------------------------------------------------------ data + boot

let booted = false;

async function refresh() {
  if (booted) document.body.classList.add("static");
  booted = true;
  [state.summary, state.extensions, state.machines, state.software, state.guard] = await Promise.all([
    Api.summary(), Api.extensions(), Api.machines(), Api.software(), Api.guard(),
  ]);
  computeMeta();
  renderActionbar();
  renderAlertbar();
  renderExtSeg();
  renderExtRows();
  renderMachinesView();
  renderSoftwareView();
  renderGuard();
  try { await renderCrown(); } catch { /* exposure is optional for the overview */ }
  renderOverview();
  renderAdd();
  watchFeeds();
  if (!state.extensions.length) $("#ext-detail").innerHTML = `<p class="empty">Pick an extension to see why it got its score.</p>`;
  if (!state.machines.length) $("#machine-detail").innerHTML = `<p class="empty">Pick a computer to see its extensions and programs.</p>`;
  if (!state.software.length) $("#sw-detail").innerHTML = "";
  $("#source").innerHTML = `<span class="lbl">Live · updated ${esc(time(new Date().toISOString()))}</span>`;
  $("#source").className = "source live";
  if (state.ext) renderExtDetail(state.ext);
  if (state.machine) renderMachine(state.machine);
  if (state.sw) renderSwDetail(state.sw);
}

async function downloadKind(kind) {
  try {
    if (kind === "chrome") download("blindspot_chrome_policy.json", JSON.stringify((await Api.policy()).chrome_policy, null, 2));
    if (kind === "contain") download("blindspot_containment_policy.json", JSON.stringify((await Api.policy("?protect_all=true")).chrome_policy, null, 2));
    if (kind === "reg") download("blindspot_policy.reg", await Api.policyReg(), "text/plain");
    if (kind === "applocker") download("blindspot_applocker.xml", await Api.applocker(), "application/xml");
    if (kind === "swjson") download("blindspot_software_policy.json", JSON.stringify(await Api.softwarePolicy(), null, 2));
  } catch (err) { toast(err.message); }
}

let signature = "";

async function poll() {
  if (document.visibilityState !== "visible") return;
  try {
    const [summary, machines] = await Promise.all([Api.summary(), Api.machines()]);
    const next = JSON.stringify([summary, machines.map((m) => [m.machine_id, m.collected_at])]);
    if (next === signature) return;
    const known = new Set(state.machines.map((m) => `${m.machine_id}|${m.collected_at}`));
    const fresh = machines.filter((m) => !known.has(`${m.machine_id}|${m.collected_at}`));
    signature = next;
    await refresh();
    if (!state.ext && state.extensions.length) renderExtDetail(state.extensions[0].id);
    if (!state.machine && state.machines.length) renderMachine(state.machines[0].machine_id);
    if (fresh.length) toast(`New report from ${fresh.map((m) => m.hostname).join(", ")}.`);
  } catch {
    $("#source").innerHTML = `<span class="lbl">Server not reachable</span>`;
    $("#source").className = "source down";
  }
}

// tooltip + spotlight, shared by every view
function bindAmbient() {
  const tip = $("#tip");
  let tipEl = null;
  const place = (e) => {
    const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
    let x = e.clientX + pad, y = e.clientY + pad;
    if (x + w > innerWidth - 8) x = e.clientX - w - pad;
    if (y + h > innerHeight - 8) y = e.clientY - h - pad;
    tip.style.left = `${x}px`; tip.style.top = `${y}px`;
  };
  document.addEventListener("pointerover", (e) => {
    const el = e.target.closest("[data-tip]");
    if (el === tipEl) return;
    tipEl = el;
    if (!el || !el.dataset.tip) { tip.classList.remove("show"); return; }
    const [first, ...rest] = el.dataset.tip.split("\n");
    tip.innerHTML = rest.length ? `<b>${esc(first)}</b>${esc(rest.join("\n"))}` : esc(first);
    tip.classList.add("show");
    place(e);
  });
  document.addEventListener("pointermove", (e) => { if (tipEl) place(e); });
  document.addEventListener("scroll", () => { tip.classList.remove("show"); tipEl = null; }, true);

  let raf = 0;
  document.addEventListener("pointermove", (e) => {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      const card = e.target.closest && e.target.closest(".card, .kpi");
      if (!card) return;
      const r = card.getBoundingClientRect();
      card.style.setProperty("--mx", `${e.clientX - r.left}px`);
      card.style.setProperty("--my", `${e.clientY - r.top}px`);
    });
  });

  // donut legend <-> arc highlighting, click to filter
  document.addEventListener("pointerover", (e) => {
    const t = e.target.closest("[data-donut]");
    $$(".donut.hl").forEach((d) => { if (!t || d !== t.closest(".donut")) d.classList.remove("hl"); });
    $$("[data-donut].on").forEach((x) => x.classList.remove("on"));
    if (!t) return;
    const root = t.closest(".donut");
    root.classList.add("hl");
    $$(`[data-donut="${t.dataset.donut}"][data-key="${CSS.escape(t.dataset.key)}"]`, root).forEach((x) => x.classList.add("on"));
  });
}

function bindNavigation() {
  document.addEventListener("click", (e) => {
    const link = e.target.closest("[data-goto]");
    if (link) { e.preventDefault(); go(link.dataset.goto); return; }
    const d = e.target.closest("[data-donut]");
    if (d) {
      if (d.dataset.donut === "dec") { go("extensions"); setExtAction(d.dataset.key); }
      if (d.dataset.donut === "sw") { go("software"); state.swStatus = d.dataset.key; state.swQuick = ""; state.swBand = ""; renderSoftwareView(); }
      return;
    }
    const ext = e.target.closest("[data-open-ext]");
    if (ext) { go("extensions"); renderExtDetail(ext.dataset.openExt); return; }
    const mach = e.target.closest("[data-open-machine]");
    if (mach) { go("machines"); renderMachine(mach.dataset.openMachine); }
  });

  $$(".nav button").forEach((b) => b.addEventListener("click", () => go(b.dataset.view)));
  window.addEventListener("resize", moveGlow);
  $("#rail-toggle").addEventListener("click", () => {
    document.body.classList.toggle("rail-mini");
    store("bs-rail", document.body.classList.contains("rail-mini") ? "mini" : "full");
    setTimeout(moveGlow, 380);
  });

  // extensions
  $("#filter").addEventListener("input", renderExtRows);
  $("#ext-seg").addEventListener("click", (e) => { const b = e.target.closest("[data-act]"); if (b) setExtAction(b.dataset.act); });
  $$("#view-extensions th[data-sort]").forEach((th) => th.addEventListener("click", () => {
    const k = th.dataset.sort;
    state.extSort = state.extSort.key === k ? { key: k, dir: -state.extSort.dir } : { key: k, dir: k === "name" || k === "recommendation" ? 1 : -1 };
    renderExtRows();
  }));
  $("#ext-rows").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-key]"); if (tr) renderExtDetail(tr.dataset.key); });

  // machines
  $("#m-filter").addEventListener("input", renderMachineList);
  const setMf = (f) => { state.mFilter = state.mFilter === f && f !== "all" ? "all" : f; renderMachinesView(); };
  $("#m-seg").addEventListener("click", (e) => { const b = e.target.closest("[data-mf]"); if (b) setMf(b.dataset.mf); });
  $("#m-legend").addEventListener("click", (e) => { const b = e.target.closest("[data-mf]"); if (b) setMf(b.dataset.mf); });
  $("#m-kpis").addEventListener("click", (e) => { const b = e.target.closest("[data-kfilter]"); if (b) setMf(b.dataset.kfilter); });
  $("#m-os").addEventListener("click", (e) => { const b = e.target.closest("[data-mos]"); if (b) { state.mOs = b.dataset.mos; renderMachinesView(); } });
  $("#m-mode").addEventListener("click", (e) => {
    const b = e.target.closest("[data-mode]");
    if (!b) return;
    state.mMode = b.dataset.mode;
    store("bs-mmode", state.mMode);
    renderMachinesView();
  });
  $("#m-canvas").addEventListener("click", (e) => { const n = e.target.closest("[data-machine]"); if (n) renderMachine(n.dataset.machine); });
  $("#m-canvas").addEventListener("keydown", (e) => {
    const n = e.target.closest("[data-machine]");
    if (n && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); renderMachine(n.dataset.machine); }
  });

  // software
  $("#sw-filter").addEventListener("input", renderSwRows);
  $("#sw-seg").addEventListener("click", (e) => { const b = e.target.closest("[data-sws]"); if (b) { state.swStatus = b.dataset.sws; renderSoftwareView(); } });
  $("#sw-hist").addEventListener("click", (e) => { const b = e.target.closest("[data-band]"); if (b) { state.swBand = state.swBand === b.dataset.band ? "" : b.dataset.band; renderSoftwareView(); } });
  $("#sw-kpis").addEventListener("click", (e) => {
    const b = e.target.closest("[data-kfilter]");
    if (!b) return;
    const f = b.dataset.kfilter;
    state.swQuick = state.swQuick === f ? "" : f;
    renderSoftwareView();
  });
  $$("#view-software th[data-ssort]").forEach((th) => th.addEventListener("click", () => {
    const k = th.dataset.ssort;
    state.swSort = state.swSort.key === k ? { key: k, dir: -state.swSort.dir } : { key: k, dir: k === "name" ? 1 : -1 };
    renderSwRows();
  }));
  $("#sw-rows").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-key]"); if (tr) renderSwDetail(tr.dataset.key); });

  // palette
  $("#palette-btn").addEventListener("click", openPalette);
  $("#palette").addEventListener("click", (e) => {
    if (e.target.id === "palette") { closePalette(); return; }
    const it = e.target.closest("[data-pi]");
    if (it) runPalette(Number(it.dataset.pi));
  });
  $("#palette-input").addEventListener("input", (e) => buildPalette(e.target.value));
  $("#palette-input").addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); palette.sel = Math.min(palette.items.length - 1, palette.sel + 1); drawPalette(); }
    if (e.key === "ArrowUp") { e.preventDefault(); palette.sel = Math.max(0, palette.sel - 1); drawPalette(); }
    if (e.key === "Enter") { e.preventDefault(); runPalette(palette.sel); }
  });
  document.addEventListener("keydown", (e) => {
    const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); $("#palette").classList.contains("hidden") ? openPalette() : closePalette(); }
    else if (e.key === "Escape" && !$("#palette").classList.contains("hidden")) closePalette();
    else if (e.key === "/" && !typing) { e.preventDefault(); openPalette(); }
  });

  $("#cmd-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("#cmd-line").textContent); toast("Command copied."); } catch { toast("Copy is not allowed here. Select the command and copy it."); }
  });
}

async function main() {
  hydrateIcons();
  if (store("bs-rail") === "mini") document.body.classList.add("rail-mini");
  applyViewOptions();
  bindViewOptions();
  bindAlertbar();
  bindAmbient();
  try {
    await Api.init();
  } catch {
    throw new Error("The Blindspot server is not running. Start it with start_server.bat (Windows) or sh start_server.sh");
  }
  $("#source").className = "source live";
  $("#report-link").href = Api.reportUrl();

  bindNavigation();
  bindAlerts();
  renderAlerts();
  $("#clear-btn").addEventListener("click", async () => {
    if (!window.confirm("Remove every computer, extension, approval and event from this server?")) return;
    try {
      await Api.clearAll();
      Object.assign(state, { ext: null, machine: null, sw: null });
      toast("All data cleared. Agents will fill it again.");
      await refresh();
    } catch (err) { toast(err.message); }
  });
  $("#dl-chrome").addEventListener("click", () => downloadKind("chrome"));
  $("#dl-applocker").addEventListener("click", () => downloadKind("applocker"));
  $("#contain-btn").addEventListener("click", () => downloadKind("contain"));
  $$("[data-dl]").forEach((b) => b.addEventListener("click", () => downloadKind(b.dataset.dl)));
  $("#sync-btn").addEventListener("click", checkFeedsNow);
  $("#feed-refresh").addEventListener("click", checkFeedsNow);
  $("#nvd-key-save").addEventListener("click", async () => {
    try {
      const r = await Api.setNvdKey($("#nvd-key").value.trim());
      $("#nvd-key").value = "";
      toast(r.api_key ? "NVD API key saved. Checks are faster now." : "NVD API key removed.");
      watchFeeds();
    } catch (err) { toast(err.message); }
  });

  await refresh();
  signature = JSON.stringify([state.summary, state.machines.map((m) => [m.machine_id, m.collected_at])]);
  setInterval(poll, 10000);
  if (state.extensions.length) renderExtDetail([...state.extensions].sort((a, b) => b.score - a.score)[0].id);
  if (state.machines.length) {
    const first = [...state.machines].sort((a, b) => RISK_ORDER.indexOf(riskOf(a)) - RISK_ORDER.indexOf(riskOf(b)))[0];
    renderMachine(first.machine_id);
  }
  const firstSw = [...state.software].sort((a, b) => (b.cvss_max || 0) - (a.cvss_max || 0))[0];
  if (firstSw) renderSwDetail(swKey(firstSw));
  const view = location.hash.slice(1);
  go(VIEWS.includes(view) ? view : "overview");
  // relative times ("3 min ago") stay current without refetching
  setInterval(() => { if (state.view === "add") renderAdd(); }, 60000);
}

main().catch((err) => {
  hydrateIcons();
  document.querySelector("main").innerHTML = `<div class="welcome"><h1>Cannot reach the server</h1><p>${esc(err.message)}.</p></div>`;
  $("#source").innerHTML = `<span class="lbl">Server not reachable</span>`;
  $("#source").className = "source down";
});
