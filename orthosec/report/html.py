"""Self-contained HTML report — the visual, shareable view of a scan.

One file, zero external requests (CSP-safe), theme-aware. The full scan data is
embedded as JSON and rendered client-side, with a profile toggle so the same
report serves engineers, AppSec, CISOs, and product leaders — "one scan, four
lenses" made interactive. Open it in a browser or attach it to a ticket / board deck.
"""
from __future__ import annotations

import datetime
import html
import json

from orthosec.core.scanner import ScanResult
from orthosec.core.taxonomy import owasp_name
from orthosec.intel.business_risk import business_risk
from orthosec.intel.compliance import compliance_exposure
from orthosec.profiles import PROFILES


def _data(result: ScanResult, exec_summary: str | None) -> dict:
    return {
        "root": result.root,
        "score": result.score,
        "grade": result.grade,
        "severity_counts": result.by_severity(),
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "exec_summary": exec_summary,
        "business_risk": business_risk(result.findings),
        "compliance": compliance_exposure(result.findings),
        "findings": [
            {
                "rule_id": f.rule_id, "title": f.title, "severity": f.severity.name,
                "sev_value": f.severity.value, "owasp": f.owasp_llm,
                "owasp_name": owasp_name(f.owasp_llm), "atlas": f.atlas,
                "location": f.location, "evidence": f.evidence,
                "remediation": f.remediation, "business": f.business_impact,
            }
            for f in result.findings
        ],
        "profiles": {
            p.id: {
                "label": p.label, "audience": p.audience,
                "severity_floor": p.severity_floor.value,
                "show_findings": p.show_findings, "show_evidence": p.show_evidence,
                "show_remediation": p.show_remediation, "show_business": p.show_business,
                "show_compliance": p.show_compliance,
            }
            for p in PROFILES.values()
        },
    }


def render_html(result: ScanResult, profile: str = "engineer",
                exec_summary: str | None = None) -> str:
    payload = json.dumps(_data(result, exec_summary))
    return (
        _TEMPLATE
        .replace("/*__DATA__*/null", payload)
        .replace("__INITIAL_PROFILE__", html.escape(profile))
        .replace("__ROOT__", html.escape(result.root))
    )


def render_fragment(result: ScanResult, profile: str = "engineer",
                    exec_summary: str | None = None) -> str:
    """Body-only fragment (style + markup + script), for hosts that supply the
    document shell (e.g. published Artifacts). Self-contained; no external requests."""
    full = render_html(result, profile=profile, exec_summary=exec_summary)
    style = full[full.index("<style>"): full.index("</style>") + len("</style>")]
    body = full[full.index("<body>") + len("<body>"): full.index("</body>")]
    return style + "\n" + body


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OrthoSec — AI Security Report</title>
<style>
  :root {
    --bg: #f5f7fa; --panel: #ffffff; --ink: #0f1720; --muted: #5b6673;
    --line: #e2e8f0; --accent: #0f9e8f; --accent-ink: #0b6f65;
    --crit: #e5484d; --high: #ef6c3b; --med: #d9a326; --low: #3f8fd6; --info: #8b95a1;
    --good: #2ea043; --shadow: 0 1px 2px rgba(15,23,32,.06), 0 8px 24px rgba(15,23,32,.06);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0b0f14; --panel: #131a22; --ink: #e6edf3; --muted: #8b98a8;
      --line: #232d38; --accent: #2bd4c0; --accent-ink: #7ff0e4;
      --crit: #ff6169; --high: #ff8a4c; --med: #e8bd4a; --low: #5aa9ef; --info: #8b95a1;
      --good: #46c265; --shadow: 0 1px 2px rgba(0,0,0,.4), 0 10px 30px rgba(0,0,0,.35);
    }
  }
  :root[data-theme="light"] {
    --bg: #f5f7fa; --panel: #ffffff; --ink: #0f1720; --muted: #5b6673;
    --line: #e2e8f0; --accent: #0f9e8f; --accent-ink: #0b6f65;
    --crit: #e5484d; --high: #ef6c3b; --med: #d9a326; --low: #3f8fd6; --info: #8b95a1;
    --good: #2ea043; --shadow: 0 1px 2px rgba(15,23,32,.06), 0 8px 24px rgba(15,23,32,.06);
  }
  :root[data-theme="dark"] {
    --bg: #0b0f14; --panel: #131a22; --ink: #e6edf3; --muted: #8b98a8;
    --line: #232d38; --accent: #2bd4c0; --accent-ink: #7ff0e4;
    --crit: #ff6169; --high: #ff8a4c; --med: #e8bd4a; --low: #5aa9ef; --info: #8b95a1;
    --good: #46c265; --shadow: 0 1px 2px rgba(0,0,0,.4), 0 10px 30px rgba(0,0,0,.35);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--ink);
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    line-height: 1.5; -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 1020px; margin: 0 auto; padding: 32px 20px 64px; }
  code, .mono { font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace; }
  header.top { display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
  .brand { font-weight: 700; letter-spacing: -.02em; font-size: 20px; }
  .brand span { color: var(--accent); }
  .sub { color: var(--muted); font-size: 13px; }
  .target { color: var(--muted); font-size: 13px; margin-top: 2px; word-break: break-all; }

  .tabs { display: flex; gap: 6px; flex-wrap: wrap; margin: 20px 0 4px; }
  .tab {
    border: 1px solid var(--line); background: var(--panel); color: var(--muted);
    padding: 7px 13px; border-radius: 999px; font-size: 13px; font-weight: 600;
    cursor: pointer; transition: .15s;
  }
  .tab:hover { color: var(--ink); }
  .tab[aria-selected="true"] { background: var(--accent); border-color: var(--accent); color: #04120f; }
  .tab:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .audience { color: var(--muted); font-size: 13px; margin: 6px 2px 0; }

  .summary { display: grid; grid-template-columns: auto 1fr; gap: 22px; align-items: center;
    background: var(--panel); border: 1px solid var(--line); border-radius: 16px;
    padding: 22px; margin: 18px 0; box-shadow: var(--shadow); }
  .ring { position: relative; width: 132px; height: 132px; }
  .ring svg { transform: rotate(-90deg); }
  .ring .score { position: absolute; inset: 0; display: grid; place-content: center; text-align: center; }
  .ring .score b { font-size: 34px; font-weight: 800; letter-spacing: -.03em; line-height: 1; }
  .ring .score .of { font-size: 12px; color: var(--muted); }
  .grade { font-size: 12px; font-weight: 700; margin-top: 4px; }
  .chips { display: flex; gap: 8px; flex-wrap: wrap; }
  .chip { display: inline-flex; align-items: center; gap: 7px; padding: 6px 11px; border-radius: 10px;
    background: var(--bg); border: 1px solid var(--line); font-size: 13px; font-weight: 600; }
  .chip .dot { width: 9px; height: 9px; border-radius: 3px; }
  .chip .n { font-variant-numeric: tabular-nums; }

  h2.section { font-size: 13px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted);
    margin: 30px 0 12px; font-weight: 700; }

  .finding { background: var(--panel); border: 1px solid var(--line); border-left-width: 4px;
    border-radius: 12px; padding: 15px 16px; margin: 10px 0; box-shadow: var(--shadow); }
  .finding .fh { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
  .sev { font-size: 11px; font-weight: 800; letter-spacing: .04em; padding: 2px 7px; border-radius: 6px; color: #fff; }
  .finding .title { font-weight: 650; }
  .finding .loc { color: var(--muted); font-size: 12.5px; }
  .meta { color: var(--muted); font-size: 12.5px; margin-top: 6px; }
  .kv { margin-top: 8px; font-size: 13.5px; }
  .kv b { color: var(--muted); font-weight: 600; }
  .ev { display: block; margin-top: 4px; padding: 8px 10px; background: var(--bg); border: 1px solid var(--line);
    border-radius: 8px; font-size: 12.5px; overflow-x: auto; white-space: pre; }
  .rid { color: var(--muted); font-size: 11px; margin-top: 8px; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px; box-shadow: var(--shadow); }
  .card .lab { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
  .card .big { font-size: 24px; font-weight: 800; letter-spacing: -.02em; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .card .note { font-size: 12px; color: var(--muted); margin-top: 6px; }
  .frameworks { display: flex; flex-direction: column; gap: 10px; }
  .fw { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 13px 15px; box-shadow: var(--shadow); }
  .fw .name { font-weight: 700; font-size: 13px; }
  .fw .ctrls { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
  .pill { font-size: 12px; padding: 3px 9px; border-radius: 999px; background: var(--bg); border: 1px solid var(--line); }

  .exec { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px;
    box-shadow: var(--shadow); white-space: pre-wrap; font-size: 14px; }
  .empty { color: var(--muted); font-size: 14px; padding: 20px; text-align: center; }
  footer { color: var(--muted); font-size: 12px; margin-top: 40px; border-top: 1px solid var(--line); padding-top: 14px; }
  @media (max-width: 560px) { .summary { grid-template-columns: 1fr; justify-items: center; text-align: center; } }
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div>
      <div class="brand">Ortho<span>Sec</span> — AI Security Report</div>
      <div class="target mono">__ROOT__</div>
    </div>
    <div class="sub" id="genstamp"></div>
  </header>

  <div class="tabs" role="tablist" aria-label="Audience profile" id="tabs"></div>
  <div class="audience" id="audience"></div>

  <section class="summary">
    <div class="ring" aria-hidden="true">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle cx="66" cy="66" r="58" fill="none" stroke="var(--line)" stroke-width="12"></circle>
        <circle id="arc" cx="66" cy="66" r="58" fill="none" stroke-width="12" stroke-linecap="round"></circle>
      </svg>
      <div class="score"><b id="scoreNum">0</b><div class="of">/ 100</div><div class="grade" id="gradeTxt"></div></div>
    </div>
    <div>
      <div class="chips" id="sevChips"></div>
      <div class="meta" id="posture-note" style="margin-top:12px"></div>
    </div>
  </section>

  <div id="business"></div>
  <div id="compliance"></div>

  <h2 class="section" id="findings-head">Findings</h2>
  <div id="findings"></div>

  <div id="execWrap" style="display:none">
    <h2 class="section">Executive Briefing</h2>
    <div class="exec" id="exec"></div>
  </div>

  <footer>Generated by OrthoSec · deterministic detectors + grounded intel · <span id="fcount"></span></footer>
</div>

<script>
const DATA = /*__DATA__*/null;
const SEV_COLOR = { CRITICAL:"var(--crit)", HIGH:"var(--high)", MEDIUM:"var(--med)", LOW:"var(--low)", INFO:"var(--info)" };
const GRADE_COLOR = { A:"var(--good)", B:"var(--good)", C:"var(--med)", D:"var(--high)", F:"var(--crit)" };
const SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
let current = "__INITIAL_PROFILE__";
const esc = s => String(s==null?"":s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const money = n => "$" + Number(n).toLocaleString("en-US");

function renderTabs() {
  const t = document.getElementById("tabs");
  t.innerHTML = "";
  for (const [id, p] of Object.entries(DATA.profiles)) {
    const b = document.createElement("button");
    b.className = "tab"; b.role = "tab"; b.textContent = p.label;
    b.setAttribute("aria-selected", id === current);
    b.onclick = () => { current = id; render(); };
    t.appendChild(b);
  }
}

function renderRing() {
  const r = 58, circ = 2 * Math.PI * r;
  const arc = document.getElementById("arc");
  arc.style.stroke = GRADE_COLOR[DATA.grade] || "var(--accent)";
  arc.setAttribute("stroke-dasharray", circ);
  arc.setAttribute("stroke-dashoffset", circ * (1 - DATA.score / 100));
  document.getElementById("scoreNum").textContent = DATA.score;
  const g = document.getElementById("gradeTxt");
  g.textContent = "GRADE " + DATA.grade; g.style.color = GRADE_COLOR[DATA.grade];
}

function renderChips() {
  const c = document.getElementById("sevChips"); c.innerHTML = "";
  let any = false;
  for (const sev of SEV_ORDER) {
    const n = DATA.severity_counts[sev]; if (!n) continue; any = true;
    const el = document.createElement("span"); el.className = "chip";
    el.innerHTML = `<span class="dot" style="background:${SEV_COLOR[sev]}"></span>`+
      `<span class="n">${n}</span> ${sev.toLowerCase()}`;
    c.appendChild(el);
  }
  if (!any) c.innerHTML = `<span class="chip"><span class="dot" style="background:var(--good)"></span>No findings — clean scan</span>`;
}

function renderBusiness(p) {
  const w = document.getElementById("business"); w.innerHTML = "";
  if (!p.show_business) return;
  const br = DATA.business_risk;
  w.innerHTML = `<h2 class="section">Business Risk</h2>
    <div class="cards">
      <div class="card"><div class="lab">Annualized loss exposure</div>
        <div class="big">${money(br.ale_low_usd)} – ${money(br.ale_high_usd)}</div>
        <div class="note">${esc(br.basis)}</div></div>
      <div class="card"><div class="lab">Top risk driver</div>
        <div class="big" style="font-size:15px;line-height:1.35">${esc((br.risk_drivers[0]||{}).consequence||"—")}</div>
        <div class="note">${esc((br.risk_drivers[0]||{}).owasp||"")} · ${(br.risk_drivers[0]||{}).max_severity||""}</div></div>
    </div>`;
}

function renderCompliance(p) {
  const w = document.getElementById("compliance"); w.innerHTML = "";
  if (!p.show_compliance) return;
  const c = DATA.compliance; const keys = Object.keys(c);
  if (!keys.length) return;
  let h = `<h2 class="section">Regulatory Exposure</h2><div class="frameworks">`;
  for (const fw of keys) {
    const pills = c[fw].map(r => `<span class="pill" title="${esc(r.description)}">${esc(r.control)}</span>`).join("");
    h += `<div class="fw"><div class="name">${esc(fw.replace(/_/g," "))}</div><div class="ctrls">${pills}</div></div>`;
  }
  document.getElementById("compliance").innerHTML = h + "</div>";
}

function renderFindings(p) {
  const head = document.getElementById("findings-head");
  const box = document.getElementById("findings"); box.innerHTML = "";
  const shown = DATA.findings.filter(f => f.sev_value >= p.severity_floor);
  if (!p.show_findings) {
    head.textContent = "Risk Drivers";
    const drivers = DATA.business_risk.risk_drivers;
    box.innerHTML = drivers.map(d =>
      `<div class="finding" style="border-left-color:${SEV_COLOR[d.max_severity]}">
        <div class="fh"><span class="sev" style="background:${SEV_COLOR[d.max_severity]}">${d.max_severity}</span>
        <span class="title">${esc(d.consequence)}</span></div>
        <div class="meta">${esc(d.owasp)} · ${d.count} finding(s)</div></div>`).join("")
      || `<div class="empty">No findings at or above this profile's threshold.</div>`;
    return;
  }
  head.textContent = "Findings";
  if (!shown.length) { box.innerHTML = `<div class="empty">No findings at or above this profile's threshold.</div>`; return; }
  for (const f of shown) {
    const el = document.createElement("div");
    el.className = "finding"; el.style.borderLeftColor = SEV_COLOR[f.severity];
    let h = `<div class="fh"><span class="sev" style="background:${SEV_COLOR[f.severity]}">${f.severity}</span>`+
      `<span class="title">${esc(f.title)}</span><span class="loc mono">${esc(f.location)}</span></div>`+
      `<div class="meta">OWASP ${esc(f.owasp)} (${esc(f.owasp_name)})${f.atlas.length?" · ATLAS "+esc(f.atlas.join(", ")):""}</div>`;
    if (p.show_evidence && f.evidence) h += `<div class="kv"><b>evidence</b><code class="ev">${esc(f.evidence)}</code></div>`;
    if (p.show_business && f.business) h += `<div class="kv"><b>business:</b> ${esc(f.business)}</div>`;
    if (p.show_remediation) h += `<div class="kv"><b>fix:</b> ${esc(f.remediation)}</div>`;
    h += `<div class="rid mono">${esc(f.rule_id)}</div>`;
    el.innerHTML = h; box.appendChild(el);
  }
  const hidden = DATA.findings.length - shown.length;
  if (hidden) { const n = document.createElement("div"); n.className = "empty";
    n.textContent = `${hidden} finding(s) below this profile's ${["","INFO","LOW","MEDIUM","HIGH","CRITICAL"][p.severity_floor]} floor — switch to AI/ML Engineer to see all.`;
    box.appendChild(n); }
}

function render() {
  const p = DATA.profiles[current];
  document.querySelectorAll(".tab").forEach((b,i) =>
    b.setAttribute("aria-selected", Object.keys(DATA.profiles)[i] === current));
  document.getElementById("audience").textContent = "View for " + p.audience + ".";
  renderRing(); renderChips(); renderBusiness(p); renderCompliance(p); renderFindings(p);
  const ew = document.getElementById("execWrap");
  if (DATA.exec_summary) { ew.style.display = ""; document.getElementById("exec").textContent = DATA.exec_summary; }
  else ew.style.display = "none";
  document.getElementById("posture-note").textContent =
    DATA.findings.length + " finding(s) · " + Object.keys(DATA.compliance).length + " regulatory framework(s) implicated";
}

document.getElementById("genstamp").textContent = "Generated " + DATA.generated;
document.getElementById("fcount").textContent = DATA.findings.length + " findings across all profiles";
renderTabs(); render();
</script>
</body>
</html>
"""
