/* DarkMoon Web UI — front-end controller */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR = { critical: "#ff3b5c", high: "#ff8a3d", medium: "#ffd23d", low: "#3ddc97", info: "#62a8ff" };

const state = {
  view: "overview",
  jobs: [],
  currentJob: null,
  es: null,
  campaigns: [],
  findings: [],
  infraCampaign: "",
};

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch (e) {}
    throw new Error(msg);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

/* ------------------------------------------------------------------ nav */
const TITLES = {
  overview: "Overview", launch: "New assessment", live: "Live console", campaigns: "Campaigns",
  findings: "Findings", infra: "Infrastructure", reports: "Reports", sessions: "Sessions",
  agents: "Agents", tools: "MCP tools", settings: "Settings",
};

function show(view) {
  state.view = view;
  $$(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  $$(".view").forEach((v) => v.classList.add("hidden"));
  $("#view-" + view).classList.remove("hidden");
  $("#view-title").textContent = TITLES[view] || view;
  const loaders = {
    overview: loadOverview, campaigns: loadCampaigns, findings: loadFindings,
    infra: loadInfra, reports: loadReports, sessions: loadSessions, agents: loadAgents,
    tools: loadTools, settings: loadSettings, live: loadJobs, launch: loadJobs,
  };
  (loaders[view] || (() => {}))();
}

$$(".nav-item").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
$("#btn-refresh").addEventListener("click", () => { refreshStatus(); show(state.view); });

/* ------------------------------------------------------------------ status */
async function refreshStatus() {
  let s = null;
  try { s = await api("/api/status"); } catch (e) { return; }
  const d = $("#pill-docker"), m = $("#pill-mcp"), p = $("#pill-provider");
  d.textContent = s.docker ? "docker ✓" : "docker ✗";
  d.className = "pill " + (s.docker ? "ok" : "bad");
  const oc = s.containers.opencode || {};
  m.textContent = oc.running ? (s.mcp_reachable ? "mcp ✓" : "mcp starting") : "mcp ✗";
  m.className = "pill " + (s.mcp_reachable ? "ok" : "bad");
  p.textContent = "llm: " + (s.provider_mode || "none");
  p.className = "pill " + (s.provider_configured ? "ok" : "bad");
  $("#stack-state").textContent =
    `opencode: ${oc.status || "?"}\ndarkmoon: ${(s.containers.darkmoon || {}).status || "?"}`;
}

/* ------------------------------------------------------------------ overview */
async function loadOverview() {
  const o = await api("/api/overview");
  const f = o.findings, c = o.campaigns;
  const stats = [
    { l: "Campaigns", n: c.total, cls: "" },
    { l: "Findings", n: f.total, cls: "" },
    { l: "Critical", n: f.by_severity.critical, cls: "crit" },
    { l: "High", n: f.by_severity.high, cls: "high" },
    { l: "Medium", n: f.by_severity.medium, cls: "med" },
    // Withdrawn / refuted records are excluded from every count above (same
    // rule as the MCP since the 2026-11-03 audit); surfaced here so the
    // auditor can see how much of the store is audit trail.
    { l: "Open (valid)", n: f.open, cls: "open" },
    { l: "Withdrawn", n: f.withdrawn ?? 0, cls: "withd" },
    { l: "Agents", n: o.agents, cls: "" },
    { l: "MCP tools", n: o.tools, cls: "" },
  ];
  $("#stat-grid").innerHTML = stats.map((s) =>
    `<div class="stat ${s.cls}"><div class="n">${esc(s.n)}</div><div class="l">${esc(s.l)}</div></div>`).join("");

  const max = Math.max(1, ...SEV_ORDER.map((k) => f.by_severity[k]));
  $("#sev-chart").innerHTML = SEV_ORDER.map((k) => `
    <div class="sev-row">
      <span style="color:${SEV_COLOR[k]}">${k}</span>
      <span class="sev-bar"><i style="width:${(f.by_severity[k] / max) * 100}%;background:${SEV_COLOR[k]}"></i></span>
      <b>${f.by_severity[k]}</b>
    </div>`).join("");

  $("#recent-campaigns").innerHTML = o.recent_campaigns.length ? o.recent_campaigns.map((c2) => `
    <div class="list-item" data-campaign="${esc(c2.id)}">
      <span>${esc(c2.target_host || c2.target_id || c2.id)} ${statusBadge(c2.status)}</span>
      <span class="meta">${esc(c2.started_at || "")}</span>
    </div>`).join("") : `<div class="hint">No campaigns yet — launch one from “New assessment”.</div>`;

  $("#recent-reports").innerHTML = o.recent_reports.length ? o.recent_reports.map((r) => `
    <div class="list-item" data-report="${esc(r.name)}">
      <span>📄 ${esc(r.name)}</span><span class="meta">${esc(r.modified_at || "")}</span>
    </div>`).join("") : `<div class="hint">No reports generated yet.</div>`;

  $$("#recent-campaigns .list-item").forEach((el) =>
    el.addEventListener("click", () => { show("campaigns"); openCampaign(el.dataset.campaign); }));
  $$("#recent-reports .list-item").forEach((el) =>
    el.addEventListener("click", () => showReport(el.dataset.report)));
}

/* ------------------------------------------------- AI scope generator */
const SCOPE_EXAMPLE = `1win — HackerOne bug bounty program

Introduction
At 1win, cybersecurity is one of our main concerns. We welcome reports on our
designated applications and infrastructure. We ensure recognition and compensation.

Program highlights
- Open Scope: rewards for all owned assets based on impact, even if not listed.
- Fast Payment: within 1 month of receiving a report.
- Gold Standard Safe Harbor.
- Top Response Efficiency above 90%.
- Signal -1.0 or higher past-year required.

Assets eligible (all in-scope assets)
Low 1.5x / Medium 1.5x / High 1.5x / Critical 1.5x multiplier

Assets:
- https://1win.com/
- https://1wintoken.com/
- https://1wtoken.com/

Campaign: $1WIN Solana smart contracts (Sale, Vesting, Burn programs)
Other $1WIN token assets — 2x multiplier. All other in-scope assets — 1.5x.

Rewards
Remote code execution (RCE) — 3000 — Critical
Unauthorized fund movement or balance crediting — 1500–2500 — Critical
Payment verification bypass or double-credit — 1500–2500 — Critical
Injections (SQLi or equivalent) — 1500 — Critical
Admin / support interface authentication bypass — 1500 — Critical
SSRF, non-blind — 1300 — High
SSRF, blind — 750 — High
Account takeover — 1500 — High
Info disclosure / IDOR / BOLA (critical data) — 1000 — High
XSS — 150 — Medium
Subdomain takeover — 50 — Low

Out of scope / exclusions
- Core ineligible findings (no PoC, version-only reports).
- Self-XSS, framing, clickjacking, social engineering.
- DoS / request flooding; automated scanners max 5 req/sec, 5 concurrent.
- Third-party vendors, games on 1win.com/casino, payment flows.
- SPF, DKIM, DMARC; SSL/TLS certificate issues; DNS config weaknesses.
- Recently disclosed (<30 days) zero-days.

Rules
Testing only on infrastructure you are authorized to test. Use your own accounts.
Valid reports need a clear description and a working PoC. Duplicates not paid.
Payments through HackerOne. Response within 15 days; bounty within ~2 weeks.`;

function openScopeAI() {
  $("#scope-ai-brief").value = "";
  $("#scope-ai-output").classList.add("hidden");
  $("#scope-ai-output").textContent = "—";
  $("#scope-ai-status").textContent = "";
  $("#scope-ai-modal").classList.remove("hidden");
  $("#scope-ai-brief").focus();
}
function closeScopeAI() { $("#scope-ai-modal").classList.add("hidden"); }

$("#btn-scope-ai").addEventListener("click", openScopeAI);
$("#scope-ai-backdrop").addEventListener("click", closeScopeAI);
$("#scope-ai-close").addEventListener("click", closeScopeAI);
$("#scope-ai-example").addEventListener("click", () => { $("#scope-ai-brief").value = SCOPE_EXAMPLE; });
$("#scope-ai-run").addEventListener("click", async () => {
  const btn = $("#scope-ai-run");
  const status = $("#scope-ai-status");
  const out = $("#scope-ai-output");
  const brief = $("#scope-ai-brief").value.trim();
  if (!brief) { status.textContent = "⚠ paste a program brief first"; return; }
  btn.disabled = true;
  status.textContent = "✨ asking the configured LLM…";
  out.classList.add("hidden");
  try {
    const r = await api("/api/scope", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ brief }),
    });
    if (!r.ok) {
      status.textContent = "✗ " + (r.error || "model failed");
      out.classList.remove("hidden");
      out.textContent = (r.raw || "").slice(-1500) || "(no raw output)";
      return;
    }
    const text = JSON.stringify(r.scope, null, 2);
    out.textContent = text;
    out.dataset.scope = text;
    out.classList.remove("hidden");
    $("#scope-ai-actions").classList.remove("hidden");
    status.textContent = `✓ generated with ${r.model || "configured model"} — review and click "Use this scope"`;
    if (r.dropped && r.dropped.length) {
      // The validator removed hosts the model invented — never present in the
      // brief. Surface them so the reviewer knows they were not silently lost.
      status.textContent += ` — ${r.dropped.length} entr${r.dropped.length === 1 ? "y" : "ies"} dropped (not in the brief): ${r.dropped.join(", ")}`;
    }
  } catch (e) {
    status.textContent = "✗ " + e.message;
  }
  btn.disabled = false;
});

// "Use this scope" button (sibling of the output block) loads the generated JSON
// back into the launch form's SCOPE field, flattened the way the CLI expects it.
$("#scope-ai-actions").addEventListener("click", (e) => {
  if (e.target.id !== "scope-ai-use") return;
  const text = $("#scope-ai-output").dataset.scope;
  if (!text) return;
  try {
    const s = JSON.parse(text);
    // Flatten the structured scope back into the launch form's SCOPE field,
    // exactly the way the CLI expects it: comma-separated assets followed by
    // the out-of-scope rules (build_prompt emits SCOPE="…").
    const assets = (s.in_scope || []).concat((s.assets || []).map((a) => a.url)).filter(Boolean);
    const exclusions = s.out_of_scope || [];
    $("#f-scope").value = assets.join(", ");
    if (exclusions.length) $("#f-note").value = exclusions.join("; ");
    // Carry the programme's own rate/automation rule into the launch: the
    // engine writes it to the shared store and enforces it mechanically.
    state.scopeRatePolicy = s.rate_limit || "";
    if (s.rate_limit) {
      const cur = $("#f-note").value;
      $("#f-note").value = cur ? cur + "\n[RATE POLICY] " + s.rate_limit : "[RATE POLICY] " + s.rate_limit;
    }
    closeScopeAI();
    statusToast("scope loaded into the launch form — tweak it and run the assessment");
  } catch (e) {
    alert("stored scope is not valid JSON: " + e.message);
  }
});

function statusToast(msg) {
  const s = $("#launch-status");
  if (s) s.textContent = msg;
}

/* ------------------------------------------------------------------ launch */
$("#btn-launch").addEventListener("click", async () => {
  const payload = {
    target: $("#f-target").value.trim(),
    program: $("#f-program").value.trim(),
    focus: $("#f-focus").value.trim(),
    noise: $("#f-noise").value,
    format: $("#f-format").value,
    scope: $("#f-scope").value.trim(),
    creds: $("#f-creds").value.trim(),
    note: $("#f-note").value.trim(),
    rate_policy: state.scopeRatePolicy || "",
  };
  if (!payload.target) { $("#launch-status").textContent = "⚠ target is required"; return; }
  $("#btn-launch").disabled = true;
  $("#btn-cancel").disabled = false;
  $("#launch-status").textContent = "starting…";
  try {
    const job = await api("/api/launch", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    state.currentJob = job.id;
    $("#launch-status").textContent = "job " + job.id;
    state.jobs.unshift(job);
    renderJobSelect();
    show("live");
    openStream(job.id);
  } catch (e) {
    $("#launch-status").textContent = "✗ " + e.message;
  } finally {
    $("#btn-launch").disabled = false;
    $("#btn-cancel").disabled = true;
  }
});

$("#btn-cancel").addEventListener("click", async () => {
  if (!state.currentJob) return;
  await api(`/api/jobs/${state.currentJob}/stop`, { method: "POST" });
  $("#launch-status").textContent = "stopped";
});

/* ------------------------------------------------------------------ live console */
async function loadJobs() {
  const { jobs } = await api("/api/jobs");
  state.jobs = jobs;
  renderJobSelect();
}

function renderJobSelect() {
  const sel = $("#job-select");
  sel.innerHTML = state.jobs.length
    ? state.jobs.map((j) => `<option value="${esc(j.id)}">${esc(j.id)} — ${esc(j.target || "")}</option>`).join("")
    : `<option value="">no job yet</option>`;
  if (state.currentJob) sel.value = state.currentJob;
}

$("#job-select").addEventListener("change", (e) => { state.currentJob = e.target.value; openStream(e.target.value); });
$("#btn-stop").addEventListener("click", async () => {
  if (!state.currentJob) return;
  await api(`/api/jobs/${state.currentJob}/stop`, { method: "POST" });
});

$("#btn-mcp-stream").addEventListener("click", async () => {
  try {
    const job = await api("/api/launch", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ kind: "mcp-stream" }),
    });
    state.currentJob = job.id;
    state.jobs.unshift(job);
    renderJobSelect();
    openStream(job.id);
  } catch (e) { alert("Could not start the MCP stream: " + e.message); }
});

function consoleLine(text) {
  const c = $("#console");
  const cls = /error|failed|exception/i.test(text) ? "err"
    : /vulnerab|finding|exploit/i.test(text) ? "find"
    : /^\s*(\$|>)/.test(text) ? "cmd" : "";
  const div = document.createElement("div");
  if (cls) div.className = cls;
  div.textContent = text;
  c.appendChild(div);
  while (c.childElementCount > 3000) c.removeChild(c.firstChild);
  c.scrollTop = c.scrollHeight;
}

function openStream(jobId) {
  if (!jobId) return;
  if (state.es) state.es.close();
  $("#console").innerHTML = "";
  $("#event-feed").innerHTML = "";
  const es = new EventSource(`/api/jobs/${jobId}/stream`);
  state.es = es;
  es.onmessage = (ev) => {
    let msg; try { msg = JSON.parse(ev.data); } catch (e) { return; }
    if (msg.type === "backlog") (msg.lines || []).forEach(consoleLine);
    else if (msg.type === "line") consoleLine(msg.line);
    else if (msg.type === "event") {
      const d = document.createElement("div");
      d.className = msg.event.kind;
      d.textContent = `${msg.event.ts} ${msg.event.text}`;
      $("#event-feed").appendChild(d);
      while ($("#event-feed").childElementCount > 300) $("#event-feed").removeChild($("#event-feed").firstChild);
    } else if (msg.type === "status" || msg.type === "end") {
      const st = msg.status || "idle";
      const t = $("#console-status");
      t.textContent = st;
      t.className = "tag " + st;
      if (st !== "running") es.close();
    }
  };
  es.onerror = () => { es.close(); };
}

/* ------------------------------------------------------------------ campaigns */
async function loadCampaigns() {
  const { campaigns, targets, projects } = await api("/api/campaigns");
  state.campaigns = campaigns;
  const rows = campaigns.length ? campaigns.map((c) => `
    <tr data-campaign="${esc(c.id)}">
      <td class="mono">${esc(c.id)}</td>
      <td>${esc(c.target_host || c.target_id || "-")}</td>
      <td>${statusBadge(c.status)}</td>
      <td>${esc(c.started_at || "-")}</td>
      <td>${esc(c.duration_seconds ?? "-")}</td>
      <td>${esc(c.findings_count ?? 0)}</td>
      <td>${esc(c.nodes_count ?? 0)}</td>
    </tr>`).join("")
    : `<tr><td colspan="7" class="hint">No campaigns recorded yet.</td></tr>`;
  $("#campaigns-table").innerHTML = `<table><thead><tr>
      <th>Campaign</th><th>Target</th><th>Status</th><th>Started</th><th>Duration</th><th>Findings</th><th>Nodes</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
  $$("#campaigns-table tbody tr[data-campaign]").forEach((tr) =>
    tr.addEventListener("click", () => openCampaign(tr.dataset.campaign)));

  const sel = $("#f-campaign");
  sel.innerHTML = `<option value="all">all campaigns</option>` +
    campaigns.map((c) => `<option value="${esc(c.id)}">${esc(c.id)} — ${esc(c.target_host || c.target_id || "")}</option>`).join("");
  const ic = $("#infra-campaign");
  ic.innerHTML = `<option value="">select a campaign…</option>` +
    campaigns.map((c) => `<option value="${esc(c.id)}">${esc(c.id)} — ${esc(c.target_host || c.target_id || "")}</option>`).join("");
}

async function openCampaign(id) {
  try {
    const { campaign, findings, infrastructure } = await api(`/api/campaigns/${encodeURIComponent(id)}`);
    openDrawer(campaign.id, `
      <dl class="kv">
        <dt>Target</dt><dd>${esc(campaign.target_host || campaign.target_id || "-")}</dd>
        <dt>Status</dt><dd>${statusBadge(campaign.status)}</dd>
        <dt>Started</dt><dd class="mono">${esc(campaign.started_at || "-")}</dd>
        <dt>Duration</dt><dd>${esc(campaign.duration_seconds ?? "-")}s</dd>
        <dt>Executive summary</dt><dd>${esc(campaign.executive_summary || "-")}</dd>
      </dl>
      <h3>Findings (${findings.length})</h3>
      ${findings.length ? findings.map(findingCard).join("") : `<div class="hint">No findings recorded.</div>`}
      <h3>Infrastructure nodes (${infrastructure.length})</h3>
      ${infrastructure.length ? `<pre class="block">${esc(JSON.stringify(infrastructure, null, 2))}</pre>` : `<div class="hint">No nodes recorded.</div>`}
    `);
  } catch (e) { alert("Could not load campaign: " + e.message); }
}

/* ------------------------------------------------------------------ findings */
function statusBadge(s) {
  // A campaign's status deserves its own colour: "running" is in flight
  // (accent), "completed" is done (green). Both rendered "neutral" before,
  // so a live campaign and a finished one looked identical in the table.
  const st = String(s || "?").toLowerCase();
  const cls = st === "running" ? "accent" : st === "completed" || st === "finished" ? "low" : "neutral";
  return `<span class="badge ${cls}">${esc(s || "?")}</span>`;
}

function findingCard(v) {
  const sev = String(v.severity || "info").toLowerCase();
  const cvss = parseFloat(v.cvss_score);
  return `<div style="border:1px solid var(--line);border-radius:9px;padding:11px 13px;margin-bottom:9px;background:var(--panel-2)">
    <div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap">
      <span class="badge ${esc(sev)}">${esc(sev)}</span>
      <b>${esc(v.title || v.id || "untitled")}</b>
      ${v.withdrawn ? '<span class="badge neutral">withdrawn / false positive</span>' : ""}
      ${Number.isFinite(cvss) && cvss > 0 ? `<span class="mono hint">CVSS ${esc(v.cvss_score)}</span>` : ""}
      ${v.cve ? `<span class="mono hint">${esc(v.cve)}</span>` : ""}
      ${v.status ? `<span class="badge neutral">${esc(v.status)}</span>` : ""}
    </div>
    ${v.description ? `<p style="margin:7px 0 0">${esc(v.description)}</p>` : ""}
    <div class="mono hint" style="margin-top:6px">${esc(v.endpoint || "")} ${esc(v.discovered_by_agent || "")} ${esc(v.mitre_attack_id || "")}</div>
    ${v.remediation ? `<div style="margin-top:7px"><b>Remediation:</b> ${esc(v.remediation)}</div>` : ""}
    ${v.evidence_commands ? `<pre class="block">${esc(Array.isArray(v.evidence_commands) ? v.evidence_commands.join("\n") : v.evidence_commands)}</pre>` : ""}
  </div>`;
}

async function loadFindings() {
  const q = $("#f-q").value.trim();
  const sev = $("#f-sev").value;
  const camp = $("#f-campaign").value;
  const showWithdrawn = $("#f-withdrawn") && $("#f-withdrawn").checked;
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (sev) params.set("severity", sev);
  if (camp && camp !== "all") params.set("campaign_id", camp);
  // The server hides withdrawn / refuted records by default so this view
  // matches the vendor-facing report (2026-11-03 audit). The checkbox
  // re-includes them, flagged, for the audit trail.
  if (showWithdrawn) params.set("include_withdrawn", "1");
  const { findings } = await api("/api/findings?" + params.toString());
  state.findings = findings;
  $("#findings-table").innerHTML = findings.length ? `<table><thead><tr>
      <th>Severity</th><th>Title</th><th>CVSS</th><th>Endpoint</th><th>Agent</th><th>CVE</th><th>MITRE</th><th>Status</th>
    </tr></thead><tbody>${findings.map((v, i) => `
      <tr data-idx="${i}" class="${v.withdrawn ? "withdrawn" : ""}">
        <td><span class="badge ${esc(String(v.severity || "info").toLowerCase())}">${esc(v.severity || "info")}</span></td>
        <td>${esc(v.title || v.id || "-")}${v.withdrawn ? ' <span class="hint">(withdrawn / false positive)</span>' : ""}</td>
        <td class="mono">${Number.isFinite(parseFloat(v.cvss_score)) && parseFloat(v.cvss_score) > 0 ? esc(v.cvss_score) : "-"}</td>
        <td class="mono">${esc(v.endpoint || "-")}</td>
        <td>${esc(v.discovered_by_agent || "-")}</td>
        <td class="mono">${esc(v.cve || "-")}</td>
        <td class="mono">${esc(v.mitre_attack_id || "-")}</td>
        <td>${esc(v.status || "-")}</td>
      </tr>`).join("")}</tbody></table>`
    : `<div class="hint">No findings match the current filter.</div>`;
  $$("#findings-table tbody tr[data-idx]").forEach((tr) =>
    tr.addEventListener("click", () => openDrawer("Finding", findingCard(state.findings[+tr.dataset.idx]))));
}

$("#f-q").addEventListener("input", debounce(loadFindings, 300));
$("#f-sev").addEventListener("change", loadFindings);
$("#f-campaign").addEventListener("change", loadFindings);
$("#f-withdrawn").addEventListener("change", loadFindings);

/* severity filter options */
$("#f-sev").innerHTML = `<option value="all">all severities</option>` +
  SEV_ORDER.map((s) => `<option value="${s}">${s}</option>`).join("");

/* ------------------------------------------------------------------ infrastructure */
async function loadInfra() {
  const sel = $("#infra-campaign");
  if (!sel.options.length) await loadCampaigns();
  const id = sel.value || state.infraCampaign;
  if (!id) { $("#infra-graph").innerHTML = `<div class="hint" style="padding:20px">Select a campaign to map its infrastructure.</div>`; return; }
  state.infraCampaign = id;
  const { nodes } = await api(`/api/infra/${encodeURIComponent(id)}`);
  renderGraph(nodes);
  $("#infra-list").innerHTML = nodes.length ? `<table><thead><tr>
      <th>Type</th><th>Label</th><th>Host</th><th>Technology</th><th>Port</th><th>Version</th><th>Risk</th>
    </tr></thead><tbody>${nodes.map((n) => `
      <tr><td>${esc(n.node_type || n.type || "-")}</td>
      <td>${esc(n.label || n.title || n.id || "-")}</td>
      <td class="mono">${esc(n.host || "-")}</td>
      <td>${esc(n.technology || "-")}</td>
      <td class="mono">${esc(n.port || "-")}</td>
      <td class="mono">${esc(n.version || "-")}</td>
      <td>${esc(n.risk_level || "-")}</td></tr>`).join("")}</tbody></table>`
    : `<div class="hint">No infrastructure nodes recorded for this campaign.</div>`;
}

function renderGraph(nodes) {
  const W = 1000, H = 380;
  if (!nodes.length) { $("#infra-graph").innerHTML = `<div class="hint" style="padding:20px">No nodes.</div>`; return; }
  // radial layout, grouped by type
  const groups = {};
  nodes.forEach((n) => { (groups[n.node_type || n.type || "other"] ||= []).push(n); });
  const types = Object.keys(groups);
  const pos = {};
  types.forEach((t, ti) => {
    const list = groups[t];
    list.forEach((n, i) => {
      const ring = Math.ceil(list.length / 6);
      const ang = (i / list.length) * Math.PI * 2 - Math.PI / 2;
      const rad = 90 + ring * 70 + (ti % 2) * 18;
      pos[n.id] = { x: W / 2 + Math.cos(ang) * rad, y: H / 2 + Math.sin(ang) * rad, n };
    });
  });
  const edges = nodes.filter((n) => n.parent_node_id && pos[n.parent_node_id])
    .map((n) => `<line x1="${pos[n.parent_node_id].x}" y1="${pos[n.parent_node_id].y}" x2="${pos[n.id].x}" y2="${pos[n.id].y}" stroke="#2b3350" stroke-width="1"/>`).join("");
  const shapes = Object.values(pos).map(({ x, y, n }) => {
    const label = (n.label || n.title || n.name || n.id || "").toString().slice(0, 22);
    return `<g><circle class="node-shape" cx="${x}" cy="${y}" r="16"/>
      <text class="node-label" x="${x}" y="${y + 30}" text-anchor="middle">${esc(label)}</text></g>`;
  }).join("");
  $("#infra-graph").innerHTML = `<svg viewBox="0 0 ${W} ${H}">${edges}${shapes}</svg>`;
}

$("#infra-campaign").addEventListener("change", loadInfra);

/* ------------------------------------------------------------------ reports */
async function loadReports() {
  const { reports } = await api("/api/reports");
  $("#reports-list").innerHTML = reports.length ? reports.map((r) => `
    <div class="list-item" data-report="${esc(r.name)}">
      <span>📄 ${esc(r.name)}</span>
      <span class="meta">${esc(r.size)} B — ${esc(r.modified_at || "")}</span>
    </div>`).join("") : `<div class="hint">No reports yet.</div>`;
  $$("#reports-list .list-item").forEach((el) =>
    el.addEventListener("click", () => showReport(el.dataset.report)));
}

async function showReport(name) {
  try {
    const md = await api(`/api/reports/${encodeURIComponent(name)}`);
    openDrawer(name, `<pre class="block">${esc(md)}</pre>`);
  } catch (e) { alert("Could not load report: " + e.message); }
}

/* ------------------------------------------------------------------ sessions */
async function loadSessions() {
  const { sessions, db_sessions } = await api("/api/sessions");
  $("#sessions-list").innerHTML = sessions.length ? sessions.map((s) => `
    <div class="list-item" data-session="${esc(s.name)}">
      <span>☰ ${esc(s.name)}</span>
      <span class="meta">${esc(s.size)} B — ${esc(s.modified_at || "")}</span>
    </div>`).join("") : `<div class="hint">No session logs on disk yet.</div>`;
  $$("#sessions-list .list-item").forEach((el) =>
    el.addEventListener("click", async () => {
      const md = await api(`/api/sessions/${encodeURIComponent(el.dataset.session)}`);
      openDrawer(el.dataset.session, `<pre class="block">${esc(md)}</pre>`);
    }));
  if (db_sessions && db_sessions.length) {
    const box = document.createElement("div");
    box.className = "card";
    box.innerHTML = `<h2>Opencode sessions (db)</h2><div class="list">` +
      db_sessions.slice(0, 60).map((s) => `
        <div class="list-item"><span class="mono">${esc(s.id)}</span>
        <span class="meta">${esc(s.title || "")} ${s.root ? "· root" : ""}</span></div>`).join("") +
      `</div>`;
    const host = $("#view-sessions");
    if (!host.querySelector("#db-sessions")) { box.id = "db-sessions"; host.appendChild(box); }
  }
}

/* ------------------------------------------------------------------ agents */
async function loadAgents() {
  const { agents, count } = await api("/api/agents");
  $("#agents-count").textContent = `${count} agents (1 orchestrator + ${count - 1} specialists)`;
  $("#agents-grid").innerHTML = agents.map((a) => `
    <div class="agent-card" data-agent="${esc(a.name)}">
      <div class="an">${a.primary ? "★ " : ""}${esc(a.name)}</div>
      <div class="ad">${esc(a.description || "")}</div>
    </div>`).join("");
  $$("#agents-grid .agent-card").forEach((el) =>
    el.addEventListener("click", () => openAgent(el.dataset.agent)));
}

async function openAgent(name) {
  const a = await api(`/api/agent/${encodeURIComponent(name)}`);
  $("#agent-detail").classList.remove("hidden");
  $("#agent-detail-title").textContent = a.name + (a.meta.primary ? " (orchestrator)" : "");
  $("#agent-detail-body").textContent = a.content;
  $("#agent-detail").scrollIntoView({ behavior: "smooth" });
}

/* ------------------------------------------------------------------ tools */
async function loadTools() {
  const t = await api("/api/tools");
  $("#tools-count").textContent = `(${t.count})`;
  $("#tools-list").innerHTML = t.allowed_tools.map((x) => `<span class="chip">${esc(x)}</span>`).join("");
  $("#workflows-list").innerHTML = t.workflows.length ? t.workflows.map((w) => `
    <div class="list-item"><span>⚙ ${esc(w.name)}</span><span class="meta">${esc(w.file)}</span></div>`).join("")
    : `<div class="hint">No workflows found.</div>`;
}

/* ------------------------------------------------------------------ settings */
async function loadSettings() {
  const env = await api("/api/env");
  $("#env-current").textContent = Object.entries(env.configured).map(([k, v]) => `${k}=${v}`).join("\n") || "(not configured)";
  const cfg = env.configured || {};
  if (cfg.OPENCODE_LOCAL_MODE) { $("#s-mode").value = "local"; $("#s-baseurl").value = cfg.OPENCODE_LOCAL_BASE_URL || ""; $("#s-model").value = cfg.OPENCODE_LOCAL_MODEL || ""; $("#s-provider").value = cfg.OPENCODE_LOCAL_PROVIDER_ID || "ollama"; }
  else if (cfg.ANTHROPIC_BASE_URL) { $("#s-mode").value = "anthropic"; $("#s-baseurl").value = cfg.ANTHROPIC_BASE_URL; $("#s-model").value = cfg.ANTHROPIC_MODEL || ""; }
  else if (cfg.OPENROUTER_PROVIDER) { $("#s-mode").value = "cloud"; $("#s-provider").value = cfg.OPENROUTER_PROVIDER; $("#s-model").value = cfg.OPENCODE_MODEL || ""; }
  if (cfg.MINIMAX_API_HOST) $("#s-minimax-host").value = cfg.MINIMAX_API_HOST;
}

$("#btn-save-env").addEventListener("click", async () => {
  const mode = $("#s-mode").value;
  const body = {
    mode, provider: $("#s-provider").value.trim(), model: $("#s-model").value.trim(),
    api_key: $("#s-key").value.trim(), base_url: $("#s-baseurl").value.trim(),
    provider_id: $("#s-provider").value.trim() || "ollama",
  };
  try {
    // The server preserves the stored MiniMax key when the body omits it, so
    // saving a provider never silently disables the MCP.
    const r = await api("/api/env", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    $("#env-status").textContent = r.applied
      ? "✓ saved and applied to the running engine"
      : "✓ saved — restart the engine to apply";
    if (r.restart_required) $("#env-status").textContent += " (on-prem mode needs a container restart)";
    loadSettings();
  } catch (e) { $("#env-status").textContent = "✗ " + e.message; }
});

$$("[data-stack]").forEach((b) => b.addEventListener("click", async () => {
  $("#stack-output").textContent = "running " + b.dataset.stack + "…";
  try {
    const r = await api(`/api/stack/${b.dataset.stack}`, { method: "POST" });
    $("#stack-output").textContent = r.output || (r.ok ? "done" : "failed");
    refreshStatus();
  } catch (e) { $("#stack-output").textContent = "✗ " + e.message; }
}));

/* ------------------------------------------------- MiniMax MCP settings */
// Saves the MiniMax M Plan MCP key alongside the provider config. The provider
// block is re-sent unchanged so saving the MCP key never drops the model.
$("#btn-save-minimax").addEventListener("click", async () => {
  const status = $("#minimax-status");
  const key = $("#s-minimax-key").value.trim();
  const host = $("#s-minimax-host").value.trim();
  if (!key) {
    status.textContent = "⚠ enter a MiniMax API key (empty key disables the MCP)";
    return;
  }
  // MiniMax-only save: send NO provider fields. The server preserves the
  // provider config already on disk (routing this through the provider
  // branches used to 400 when the provider form was empty).
  const body = {
    minimax_api_key: key,
    minimax_api_host: host || "https://api.minimax.io",
  };
  try {
    const r = await api("/api/env", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    status.textContent = r.applied
      ? "✓ saved — MiniMax MCP registered (web_search + understand_image)"
      : "✓ saved — restart the engine to apply";
    $("#s-minimax-key").value = "";
    loadSettings();
    refreshStatus();
  } catch (e) { status.textContent = "✗ " + e.message; }
});

/* ------------------------------------------------------------------ drawer */
function openDrawer(title, html) {
  $("#drawer-title").textContent = title;
  $("#drawer-body").innerHTML = html;
  $("#drawer").classList.remove("hidden");
  $("#overlay").classList.remove("hidden");
}
$("#drawer-close").addEventListener("click", closeDrawer);
$("#overlay").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeDrawer(); if (!$("#scope-ai-modal").classList.contains("hidden")) closeScopeAI(); }
  });
function closeDrawer() { $("#drawer").classList.add("hidden"); $("#overlay").classList.add("hidden"); }

/* ------------------------------------------------------------------ utils */
function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

/* ------------------------------------------------------------------ boot */
(async function boot() {
  show("overview");
  refreshStatus();
  setInterval(refreshStatus, 15000);
  try { await loadFindings(); } catch (e) {}
})();
