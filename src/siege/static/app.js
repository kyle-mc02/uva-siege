// siege operator UI.
//
// RULE: every string from the API may be attacker-controlled (banners, titles,
// hostnames, filenames). Only ever put it in the DOM via textContent / el().
// Never innerHTML. Cytoscape draws labels on a canvas, so graph labels are safe.
"use strict";

const STATE_COLORS = {
  discovered: "#5b6773", enumerated: "#3f7fbf", vulnerable: "#c9a227",
  foothold: "#d9822b", owned: "#c23b3b", out_of_scope: "#2a2a2a",
};

let cy = null;
let currentHost = null;
let hostList = [];

// --- auth: token comes in the URL once, then lives in localStorage ----------
function getToken() {
  const u = new URL(location.href);
  const fromUrl = u.searchParams.get("token");
  if (fromUrl) {
    try { localStorage.setItem("siege_token", fromUrl); } catch (_) {}
    u.searchParams.delete("token");
    history.replaceState(null, "", u.pathname + u.search);  // keep token out of the address bar
    return fromUrl;
  }
  try { return localStorage.getItem("siege_token") || ""; } catch (_) { return ""; }
}
const TOKEN = getToken();
const withToken = (path) => path + (path.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(TOKEN);

// --- operator identity: tags everything you add; persisted per browser --------
function operator() {
  const v = (document.getElementById("operator").value || "").trim();
  return v || "operator";
}
(function initOperator() {
  const el = document.getElementById("operator");
  try { el.value = localStorage.getItem("siege_operator") || ""; } catch (_) {}
  el.addEventListener("change", () => {
    try { localStorage.setItem("siege_operator", el.value.trim()); } catch (_) {}
  });
})();

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "checked") node.checked = !!v;
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function status(msg, isError = false) {
  const s = document.getElementById("status");
  s.textContent = msg;
  s.className = isError ? "error" : "";
}

async function api(path, opts = {}) {
  const headers = new Headers(opts.headers || {});
  headers.set("Authorization", "Bearer " + TOKEN);
  if (opts.method && opts.method !== "GET") headers.set("X-Requested-By", "siege");
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 204) return null;
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch (_) {}
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
}

function hostLabel(d) {
  const name = d.hostname ? `${d.ip}\n${d.hostname}` : d.ip;
  const ports = d.open_ports ? `${d.open_ports} open` : "no open ports";
  const ev = d.evidence ? ` · ${d.evidence} ev` : "";
  return `${name}\n${ports}${ev}`;
}

async function loadGraph() {
  const g = await api("/api/graph");
  document.getElementById("engagement").textContent = g.engagement;
  document.title = `siege — ${g.engagement}`;
  for (const e of g.elements) if (e.data.kind === "host") e.data.label = hostLabel(e.data);

  if (!cy) {
    cy = cytoscape({
      container: document.getElementById("graph"),
      wheelSensitivity: 0.3,
      style: [
        { selector: "node[kind = 'subnet']", style: {
          "label": "data(label)", "text-valign": "top", "text-halign": "center", "color": "#7d8794",
          "font-size": 12, "background-color": "#161c23", "background-opacity": 0.6,
          "border-color": "#2a333d", "border-width": 1, "padding": 18, "shape": "round-rectangle", "text-wrap": "wrap" } },
        { selector: "node[kind = 'host']", style: {
          "label": "data(label)", "text-wrap": "wrap", "text-valign": "bottom", "text-margin-y": 4,
          "color": "#d8dee6", "font-size": 10, "width": "mapData(open_ports, 0, 20, 22, 48)",
          "height": "mapData(open_ports, 0, 20, 22, 48)", "background-color": "#5b6773",
          "border-width": 2, "border-color": "#0f1419" } },
        ...Object.entries(STATE_COLORS).map(([s, c]) => ({
          selector: `node[state = '${s}']`, style: { "background-color": c } })),
        { selector: "node[kind = 'host'][!in_scope]", style: {
          "border-color": "#ff3b3b", "border-style": "dashed", "border-width": 3 } },
        // AD emphasis (shown for both Windows and Linux domain boxes).
        { selector: "node[kind = 'host'][?ad_high_value]", style: {
          "border-color": "#f0c419", "border-width": 5, "background-blacken": -0.2 } },
        { selector: "node[kind = 'host'][?ad_is_dc]", style: { "shape": "diamond", "width": 40, "height": 40 } },
        { selector: "node:selected", style: { "border-color": "#4ea1ff", "border-width": 3 } },
        { selector: "edge", style: { "width": 1.5, "line-color": "#3a4552", "curve-style": "bezier",
          "label": "data(label)", "font-size": 8, "color": "#7d8794", "text-rotation": "autorotate",
          "target-arrow-shape": "triangle", "target-arrow-color": "#3a4552" } },
        { selector: "edge[type = 'creds_reuse']", style: { "line-color": "#c9a227", "target-arrow-color": "#c9a227", "line-style": "dashed" } },
        { selector: "edge[type = 'pivot']", style: { "line-color": "#d9822b", "target-arrow-color": "#d9822b", "width": 2.5 } },
      ],
    });
    cy.on("tap", "node[kind = 'host']", (evt) => showHost(evt.target.data("host_id")));
  }
  const pos = {};
  cy.nodes().forEach((n) => (pos[n.id()] = n.position()));
  cy.batch(() => { cy.elements().remove(); cy.add(g.elements); });
  // Reuse prior positions so live refreshes don't jump the whole board around.
  const fresh = cy.nodes().filter((n) => !pos[n.id()]);
  cy.nodes().forEach((n) => { if (pos[n.id()]) n.position(pos[n.id()]); });
  if (fresh.length || cy.nodes().length === fresh.length) {
    cy.layout({ name: "cose", animate: false, nodeDimensionsIncludeLabels: true, padding: 30 }).run();
  }
}

async function loadScope() {
  const s = await api("/api/scope");
  const banner = document.getElementById("scope-banner");
  if (!s.rules.length) { banner.hidden = true; return; }
  banner.hidden = false;
  banner.textContent = `Scope loaded: ${s.rules.filter((r) => r.in_scope).length} include / ` +
    `${s.rules.filter((r) => !r.in_scope).length} exclude rule(s). ` +
    (s.out_of_scope_hosts ? `${s.out_of_scope_hosts} host(s) OUT OF SCOPE.` : "all known hosts in scope.");
  banner.className = s.out_of_scope_hosts ? "warn" : "";
}

function fact(dl, k, v) {
  if (v == null || v === "") return;
  dl.append(el("dt", {}, k), el("dd", {}, v));
}

async function showHost(hostId) {
  const d = await api(`/api/hosts/${hostId}`);
  currentHost = d;
  const h = d.host;
  document.getElementById("panel-empty").hidden = true;
  document.getElementById("detail").hidden = false;
  document.getElementById("d-title").textContent = h.hostname ? `${h.ip} (${h.hostname})` : h.ip;
  document.getElementById("d-oos").hidden = !!h.in_scope;

  const sf = document.getElementById("state-form");
  sf.state.value = h.state;
  sf.in_scope.checked = !!h.in_scope;

  const dl = document.getElementById("d-facts");
  dl.replaceChildren();
  fact(dl, "OS", h.os);
  fact(dl, "OS family", h.os_family);
  if (h.domain) {  // AD facts only for domain-joined boxes
    fact(dl, "Domain", h.domain);
    fact(dl, "FQDN", h.dns_name);
    fact(dl, "AD", [h.ad_is_dc ? "domain controller" : null, h.ad_high_value ? "HIGH VALUE" : null].filter(Boolean).join(" · ") || "domain-joined");
  }
  fact(dl, "MAC", h.mac);
  fact(dl, "First seen", h.first_seen);
  fact(dl, "Last seen", h.last_seen);
  fact(dl, "Source", h.source_file);

  const tbody = document.getElementById("d-services");
  tbody.replaceChildren(...d.services.map((s) => el("tr", {},
    el("td", {}, `${s.port}/${s.proto}`, s.state && s.state !== "open" ? el("div", { class: "muted" }, s.state) : null),
    el("td", {}, s.name || ""),
    el("td", {}, [s.product, s.version].filter(Boolean).join(" "),
      s.banner ? el("div", { class: "banner" }, s.banner) : null),
  )));
  if (!d.services.length) tbody.append(el("tr", {}, el("td", { colspan: "3", class: "muted" }, "none recorded")));

  const fl = document.getElementById("d-findings");
  fl.replaceChildren(...d.findings.map((f) => {
    // Inline severity edit: changing the dropdown PATCHes the finding.
    const sevSel = el("select", {});
    for (const s of ["info", "low", "medium", "high", "critical"]) {
      const o = el("option", {}, s);
      if (s === f.severity) o.selected = true;
      sevSel.append(o);
    }
    sevSel.addEventListener("change", async () => {
      try { await api(`/api/findings/${f.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ severity: sevSel.value }) }); await showHost(hostId); await loadGraph(); }
      catch (err) { status(err.message, true); }
    });
    const del = el("button", { type: "button", class: "x", title: "delete finding" }, "✕");
    del.addEventListener("click", async () => {
      try { await api(`/api/findings/${f.id}`, { method: "DELETE" }); await showHost(hostId); }
      catch (err) { status(err.message, true); }
    });
    return el("li", {}, sevSel, " ", f.title, " ", del,
      f.created_by && f.created_by !== "operator" ? el("span", { class: "muted" }, ` · ${f.created_by}`) : null);
  }));

  // Existing edges where this host is the source, with a delete control.
  const edges = await api(`/api/graph`);
  const mine = edges.elements.filter((e) => e.group === "edges" && e.data.source === `host:${hostId}`);
  const byId = Object.fromEntries(edges.elements.filter((e) => e.data.kind === "host").map((e) => [e.data.id, e.data]));
  const ulE = document.getElementById("d-edges");
  ulE.replaceChildren(...mine.map((e) => {
    const dst = byId[e.data.target];
    const del = el("button", { type: "button", class: "link" }, "remove");
    del.addEventListener("click", async () => {
      try { await api(`/api/edges/${e.data.id.split(":")[1]}`, { method: "DELETE" }); await showHost(hostId); await loadGraph(); }
      catch (err) { status(err.message, true); }
    });
    return el("li", {},
      `${e.data.type} → ${dst ? dst.ip : e.data.target}`, e.data.label ? ` [${e.data.label}]` : "", " ", del,
      e.data.description ? el("div", { class: "muted" }, e.data.description) : null);
  }));

  const evl = document.getElementById("d-evidence");
  evl.replaceChildren(...d.evidence.map((e) => {
    const t = e.target;
    const where = t.type === "service" ? `${t.port}/${t.proto}` : t.type === "finding" ? `finding: ${t.finding}` : "host";
    const del = el("button", { type: "button", class: "x", title: "delete evidence" }, "✕");
    del.addEventListener("click", async () => {
      try { await api(`/api/evidence/${e.id}`, { method: "DELETE" }); await showHost(hostId); await loadGraph(); }
      catch (err) { status(err.message, true); }
    });
    return el("li", {},
      el("a", { href: withToken(`/api/evidence/${e.id}/content`), target: "_blank", rel: "noopener noreferrer" },
        e.original_name || e.kind),
      ` — ${e.kind} on ${where} `, del,
      e.caption ? el("div", { class: "muted" }, e.caption) : null,
      el("div", { class: "muted" }, `sha256 ${e.sha256.slice(0, 16)}… · ${e.added_by}`));
  }));

  // Evidence target + edge destination selects.
  document.getElementById("ev-target").replaceChildren(
    el("option", { value: `host_id:${h.id}` }, `host ${h.ip}`),
    ...d.services.map((s) => el("option", { value: `service_id:${s.id}` }, `service ${s.port}/${s.proto} ${s.name || ""}`)),
    ...d.findings.map((f) => el("option", { value: `finding_id:${f.id}` }, `finding: ${f.title}`)),
  );
  document.getElementById("edge-dst").replaceChildren(
    ...hostList.filter((x) => x.id !== h.id).map((x) => el("option", { value: x.id }, `${x.ip}${x.hostname ? " " + x.hostname : ""}`)),
  );
}

// --- forms ------------------------------------------------------------------
async function refreshAll() {
  hostList = await api("/api/hosts");
  await loadGraph();
  await loadScope();
  if (currentHost) await showHost(currentHost.host.id);
}

document.getElementById("export-link").addEventListener("click", (ev) => {
  ev.preventDefault();
  window.open(withToken("/api/export/evidence.zip"), "_blank");
});

document.getElementById("import-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  fd.set("tool", "nmap");
  try {
    const r = await api("/api/import", { method: "POST", body: fd });
    status(`imported ${r.source_file}: ${r.hosts} hosts, ${r.services} services`);
    ev.target.reset();
    await refreshAll();
  } catch (e) { status(`import failed — ${e.message}`, true); }
});

document.getElementById("bh-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await api("/api/import/bloodhound", { method: "POST", body: new FormData(ev.target) });
    const unmatched = r.unmatched.length ? `; ${r.unmatched.length} unmatched (not scanned)` : "";
    status(`bloodhound: annotated ${r.matched.length} host(s)${unmatched}`);
    ev.target.reset();
    await refreshAll();
  } catch (e) { status(`bloodhound import failed — ${e.message}`, true); }
});

document.getElementById("faraday-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await api("/api/import/faraday", { method: "POST", body: new FormData(ev.target) });
    status(`faraday: ${r.hosts} hosts, ${r.services} services, ${r.findings_new} new finding(s)`);
    ev.target.reset();
    await refreshAll();
  } catch (e) { status(`faraday import failed — ${e.message}`, true); }
});

document.getElementById("scope-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await api("/api/scope", { method: "POST", body: new FormData(ev.target) });
    status(`scope: ${r.includes} include / ${r.excludes} exclude; ${r.hosts_reclassified} host(s) reclassified`);
    ev.target.reset();
    await refreshAll();
  } catch (e) { status(`scope failed — ${e.message}`, true); }
});

document.getElementById("subnets-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await api("/api/subnets", { method: "POST", body: new FormData(ev.target) });
    status(`subnets: ${r.subnets} grouping subnet(s) defined`);
    ev.target.reset();
    await refreshAll();
  } catch (e) { status(`subnets import failed — ${e.message}`, true); }
});

document.getElementById("state-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentHost) return;
  try {
    await api(`/api/hosts/${currentHost.host.id}`, {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state: ev.target.state.value, in_scope: ev.target.in_scope.checked, actor: operator() }),
    });
    await refreshAll();
  } catch (e) { status(`update failed — ${e.message}`, true); }
});

document.getElementById("delete-host").addEventListener("click", async () => {
  if (!currentHost) return;
  const h = currentHost.host;
  if (!confirm(`Delete ${h.ip}${h.hostname ? " (" + h.hostname + ")" : ""} and all its services, findings and evidence? This cannot be undone.`)) return;
  try {
    await api(`/api/hosts/${h.id}?actor=${encodeURIComponent(operator())}`, { method: "DELETE" });
    currentHost = null;
    document.getElementById("detail").hidden = true;
    document.getElementById("panel-empty").hidden = false;
    status(`deleted host ${h.ip}`);
    await refreshAll();
  } catch (e) { status(`delete failed — ${e.message}`, true); }
});

document.getElementById("finding-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentHost) return;
  const fd = new FormData(ev.target);
  try {
    await api("/api/findings", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host_id: currentHost.host.id, title: fd.get("title"), severity: fd.get("severity"), created_by: operator() }),
    });
    ev.target.reset();
    await showHost(currentHost.host.id);
  } catch (e) { status(`finding failed — ${e.message}`, true); }
});

document.getElementById("edge-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentHost) return;
  const fd = new FormData(ev.target);
  const src = currentHost.host.id, dst = Number(fd.get("dst")), bhEdge = (fd.get("bh_edge") || "").trim();
  try {
    if (bhEdge) {
      // Route through the path logic so the edge gets an OS-aware description.
      await api("/api/attack-path", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: [src, dst], steps: [{ edge: bhEdge, type: fd.get("type") }], created_by: operator() }),
      });
    } else {
      await api("/api/edges", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ src_host_id: src, dst_host_id: dst, type: fd.get("type"), label: fd.get("label") || null, created_by: operator() }),
      });
    }
    ev.target.reset();
    await showHost(src);
    await loadGraph();
  } catch (e) { status(`edge failed — ${e.message}`, true); }
});

document.getElementById("evidence-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!currentHost) return;
  const form = new FormData(ev.target);
  const [field, id] = String(form.get("target")).split(":");
  const fd = new FormData();
  fd.set(field, id);
  fd.set("kind", form.get("kind"));
  fd.set("added_by", operator());
  if (form.get("caption")) fd.set("caption", form.get("caption"));
  const file = form.get("file");
  if (file && file.size) fd.set("file", file);
  else if (form.get("note")) fd.set("note", form.get("note"));
  else { status("choose a file or write a note", true); return; }
  try {
    await api("/api/evidence", { method: "POST", body: fd });
    ev.target.reset();
    status("evidence attached");
    await showHost(currentHost.host.id);
    await loadGraph();
  } catch (e) { status(`evidence failed — ${e.message}`, true); }
});

// --- live updates -----------------------------------------------------------
function connectWS() {
  const dot = document.getElementById("live");
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(TOKEN)}`);
  ws.onopen = () => { dot.className = "dot on"; };
  ws.onclose = () => { dot.className = "dot off"; setTimeout(connectWS, 2000); };  // auto-reconnect
  ws.onmessage = () => { refreshAll().catch((e) => status(e.message, true)); };
}

refreshAll().then(connectWS).catch((e) => status(`could not load — ${e.message}`, true));
