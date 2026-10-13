// siege wallboard (read-only). Big graph + live stats + activity ticker.
// Same untrusted-string rule as app.js: text only, never innerHTML.
"use strict";

const STATE_COLORS = {
  discovered: "#5b6773", enumerated: "#3f7fbf", vulnerable: "#c9a227",
  foothold: "#d9822b", owned: "#c23b3b", out_of_scope: "#2a2a2a",
};
const STATES = ["discovered", "enumerated", "vulnerable", "foothold", "owned"];

function token() {
  const u = new URL(location.href);
  const t = u.searchParams.get("token");
  if (t) { try { localStorage.setItem("siege_token", t); } catch (_) {} return t; }
  try { return localStorage.getItem("siege_token") || ""; } catch (_) { return ""; }
}
const TOKEN = token();

async function api(path) {
  const res = await fetch(path, { headers: { Authorization: "Bearer " + TOKEN } });
  if (!res.ok) throw new Error(res.status + "");
  return res.json();
}
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (n.className = v) : n.setAttribute(k, v);
  for (const c of kids) if (c != null) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}

let cy = null;
let lastEventId = 0;

function hostLabel(d) {
  return (d.hostname ? `${d.ip}\n${d.hostname}` : d.ip) + (d.open_ports ? `\n${d.open_ports} open` : "");
}

async function loadGraph() {
  const g = await api("/api/graph");
  document.getElementById("wall-title").textContent = g.engagement;
  document.title = `siege — ${g.engagement}`;
  for (const e of g.elements) if (e.data.kind === "host") e.data.label = hostLabel(e.data);
  if (!cy) {
    cy = cytoscape({
      container: document.getElementById("wall-graph"), userZoomingEnabled: false, userPanningEnabled: false,
      style: [
        { selector: "node[kind='subnet']", style: { "label": "data(label)", "text-valign": "top", "color": "#7d8794",
          "font-size": 16, "background-color": "#121820", "background-opacity": 0.6, "border-color": "#2a333d",
          "border-width": 1, "padding": 24, "shape": "round-rectangle", "text-wrap": "wrap" } },
        { selector: "node[kind='host']", style: { "label": "data(label)", "text-wrap": "wrap", "text-valign": "bottom",
          "text-margin-y": 5, "color": "#d8dee6", "font-size": 13, "width": 30, "height": 30,
          "background-color": "#5b6773", "border-width": 2, "border-color": "#0b0f13" } },
        ...Object.entries(STATE_COLORS).map(([s, c]) => ({ selector: `node[state='${s}']`, style: { "background-color": c } })),
        { selector: "node[kind='host'][!in_scope]", style: { "border-color": "#ff3b3b", "border-style": "dashed", "border-width": 3 } },
        { selector: "node[kind='host'][?ad_high_value]", style: { "border-color": "#f0c419", "border-width": 5 } },
        { selector: "node[kind='host'][?ad_is_dc]", style: { "shape": "diamond", "width": 40, "height": 40 } },
        { selector: "edge", style: { "width": 2, "line-color": "#3a4552", "curve-style": "bezier",
          "target-arrow-shape": "triangle", "target-arrow-color": "#3a4552" } },
        { selector: "edge[type='pivot']", style: { "line-color": "#d9822b", "target-arrow-color": "#d9822b", "width": 3 } },
        { selector: "edge[type='creds_reuse']", style: { "line-color": "#c9a227", "target-arrow-color": "#c9a227", "line-style": "dashed" } },
      ],
    });
  }
  const pos = {};
  cy.nodes().forEach((n) => (pos[n.id()] = n.position()));
  cy.batch(() => { cy.elements().remove(); cy.add(g.elements); });
  const fresh = cy.nodes().filter((n) => !pos[n.id()]);
  cy.nodes().forEach((n) => { if (pos[n.id()]) n.position(pos[n.id()]); });
  if (fresh.length) cy.layout({ name: "cose", animate: false, nodeDimensionsIncludeLabels: true, padding: 40 }).run();
  cy.fit(undefined, 40);

  renderStats(g.elements);
}

function renderStats(elements) {
  const hosts = elements.filter((e) => e.data.kind === "host").map((e) => e.data);
  const counts = Object.fromEntries(STATES.map((s) => [s, 0]));
  let oos = 0;
  for (const h of hosts) { if (!h.in_scope) oos++; if (counts[h.state] != null) counts[h.state]++; }
  const stats = document.getElementById("wall-stats");
  stats.replaceChildren(
    el("div", { class: "stat" }, el("b", {}, String(hosts.length)), el("span", {}, "hosts")),
    el("div", { class: "stat" }, el("b", {}, String(counts.owned)), el("span", {}, "owned")),
    el("div", { class: "stat" }, el("b", {}, String(counts.foothold + counts.vulnerable)), el("span", {}, "footholds / vuln")),
    el("div", { class: "stat" }, el("b", {}, String(oos)), el("span", {}, "out of scope")),
  );
}

const EVENT_TEXT = {
  import: (p) => p.tool === "bloodhound"
    ? `imported BloodHound: ${p.matched ?? "?"} host(s) annotated`
    : `imported ${p.source_file || "scan"}: ${p.hosts ?? "?"} host(s)`,
  state_change: (p) => `${p.ip || "host"} → ${p.to || "?"}`,
  evidence_added: () => `evidence pinned`,
  edge_added: (p) => `edge drawn (${p.type || "link"})`,
  finding_added: (p) => `finding: ${p.title || ""} [${p.severity || "info"}]`,
  scope_set: (p) => `scope updated (${p.hosts_changed ?? 0} hosts reclassified)`,
};

async function loadTicker() {
  const events = await api("/api/events?limit=40");
  if (events.length) lastEventId = Math.max(lastEventId, events[0].id);
  const ul = document.getElementById("wall-ticker");
  ul.replaceChildren(...events.map((ev) => {
    let payload = {};
    try { payload = JSON.parse(ev.payload || "{}"); } catch (_) {}
    const text = (EVENT_TEXT[ev.type] || (() => ev.type))(payload);
    const t = (ev.ts || "").slice(11, 19);
    return el("li", {}, el("time", {}, t), text);
  }));
}

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(TOKEN)}`);
  ws.onmessage = () => { loadGraph().catch(() => {}); loadTicker().catch(() => {}); };
  ws.onclose = () => setTimeout(connectWS, 2000);
}

Promise.all([loadGraph(), loadTicker()]).then(connectWS).catch(() => {
  document.getElementById("wall-title").textContent = "siege — connection error (check token)";
});
