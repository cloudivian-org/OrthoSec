"""Self-contained HTML report — the visual, shareable view of a scan.

One file, zero external requests (CSP-safe), theme-aware. Full scan data is
embedded as JSON and rendered client-side, with a profile toggle so the same
report serves engineers, AppSec, CISOs, and product leaders. Each finding is
routed to a remediation agent; select findings to build a `orthosec remediate`
command. The executive briefing (LLM markdown) is rendered as formatted HTML.
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
from orthosec.remediation import assign


def _data(result: ScanResult, exec_summary: str | None) -> dict:
    assign(result.findings)  # ensure remediation-agent metadata is present
    return {
        "root": result.root,
        "score": result.score,
        "grade": result.grade,
        "severity_counts": result.by_severity(),
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "exec_summary": exec_summary,
        "business_risk": business_risk(result.findings),
        "compliance": compliance_exposure(result.findings),
        "owasp_names": {f"LLM{i:02d}": owasp_name(f"LLM{i:02d}") for i in range(1, 11)},
        "findings": [
            {
                "rule_id": f.rule_id, "title": f.title, "severity": f.severity.name,
                "sev_value": f.severity.value, "owasp": f.owasp_llm,
                "owasp_name": owasp_name(f.owasp_llm), "atlas": f.atlas,
                "confidence": round(f.confidence, 2),
                "trace": f.metadata.get("trace", []),
                "location": f.location, "evidence": f.evidence,
                "remediation": f.remediation, "business": f.business_impact,
                "agent": f.metadata.get("agent_name", "Manual Review Agent"),
                "agent_id": f.metadata.get("agent_id", "review"),
                "auto": bool(f.metadata.get("auto_available")),
                "plan": f.metadata.get("plan", []),
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
    --bg: #f4f7fa; --panel: #ffffff; --panel2: #f8fafc; --ink: #0f1720; --muted: #5b6673;
    --line: #e4e9f0; --accent: #0f9e8f; --accent-ink: #04120f;
    --crit: #e5484d; --high: #ef6c3b; --med: #d9a326; --low: #3f8fd6; --info: #8b95a1;
    --good: #2ea043; --shadow: 0 1px 2px rgba(15,23,32,.05), 0 10px 26px rgba(15,23,32,.05);
    --radius: 14px;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0b0f14; --panel:#131a22; --panel2:#0f151c; --ink:#e6edf3; --muted:#8b98a8;
      --line:#232d38; --accent:#2bd4c0; --accent-ink:#04120f; --crit:#ff6169; --high:#ff8a4c;
      --med:#e8bd4a; --low:#5aa9ef; --info:#8b95a1; --good:#46c265;
      --shadow:0 1px 2px rgba(0,0,0,.4), 0 12px 30px rgba(0,0,0,.35); }
  }
  :root[data-theme="light"] { --bg:#f4f7fa; --panel:#fff; --panel2:#f8fafc; --ink:#0f1720; --muted:#5b6673;
    --line:#e4e9f0; --accent:#0f9e8f; --accent-ink:#04120f; --crit:#e5484d; --high:#ef6c3b;
    --med:#d9a326; --low:#3f8fd6; --info:#8b95a1; --good:#2ea043;
    --shadow:0 1px 2px rgba(15,23,32,.05), 0 10px 26px rgba(15,23,32,.05); }
  :root[data-theme="dark"] { --bg:#0b0f14; --panel:#131a22; --panel2:#0f151c; --ink:#e6edf3; --muted:#8b98a8;
    --line:#232d38; --accent:#2bd4c0; --accent-ink:#04120f; --crit:#ff6169; --high:#ff8a4c;
    --med:#e8bd4a; --low:#5aa9ef; --info:#8b95a1; --good:#46c265;
    --shadow:0 1px 2px rgba(0,0,0,.4), 0 12px 30px rgba(0,0,0,.35); }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; line-height:1.55;
    -webkit-font-smoothing: antialiased; }
  .wrap { max-width: 1040px; margin: 0 auto; padding: 34px 20px 120px; }
  code, .mono { font-family: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace; }
  header.top { display:flex; align-items:baseline; justify-content:space-between; flex-wrap:wrap; gap:8px; }
  .brand { font-weight:800; letter-spacing:-.02em; font-size:21px; }
  .brand span { color:var(--accent); }
  .sub { color:var(--muted); font-size:13px; }
  .target { color:var(--muted); font-size:12.5px; margin-top:3px; word-break:break-all; }

  .tabs { display:flex; gap:6px; flex-wrap:wrap; margin:22px 0 4px; }
  .tab { border:1px solid var(--line); background:var(--panel); color:var(--muted);
    padding:7px 14px; border-radius:999px; font-size:13px; font-weight:600; cursor:pointer; transition:.15s; }
  .tab:hover { color:var(--ink); border-color:var(--accent); }
  .tab[aria-selected="true"] { background:var(--accent); border-color:var(--accent); color:var(--accent-ink); }
  .tab:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  .audience { color:var(--muted); font-size:13px; margin:8px 2px 0; }

  .summary { display:grid; grid-template-columns:auto 1fr; gap:24px; align-items:center;
    background:var(--panel); border:1px solid var(--line); border-radius:var(--radius);
    padding:22px 24px; margin:18px 0; box-shadow:var(--shadow); }
  .ring { position:relative; width:132px; height:132px; }
  .ring svg { transform:rotate(-90deg); }
  .ring .score { position:absolute; inset:0; display:grid; place-content:center; text-align:center; }
  .ring .score b { font-size:36px; font-weight:800; letter-spacing:-.03em; line-height:1; font-variant-numeric:tabular-nums; }
  .ring .score .of { font-size:12px; color:var(--muted); }
  .grade { font-size:11px; font-weight:800; margin-top:5px; letter-spacing:.05em; }
  .chips { display:flex; gap:8px; flex-wrap:wrap; }
  .chip { display:inline-flex; align-items:center; gap:7px; padding:6px 11px; border-radius:10px;
    background:var(--panel2); border:1px solid var(--line); font-size:13px; font-weight:600; }
  .chip .dot { width:9px; height:9px; border-radius:3px; }
  .chip .n { font-variant-numeric:tabular-nums; }
  .sevbar { display:flex; height:9px; border-radius:6px; overflow:hidden; margin-top:14px; border:1px solid var(--line); background:var(--panel2); }
  .sevbar span { display:block; min-width:2px; }
  .owaspwrap { margin:2px 0 4px; }
  .owasp { display:flex; gap:6px; flex-wrap:wrap; }
  .ocat { font-size:11px; font-weight:750; letter-spacing:.02em; padding:4px 9px; border-radius:8px;
    border:1px solid var(--line); background:var(--panel2); color:var(--muted); }
  .ocat.hit { color:#fff; border-color:transparent; }
  .ocat .oc-n { font-variant-numeric:tabular-nums; opacity:.85; margin-left:3px; }
  .btnp { border:1px solid var(--line); background:var(--panel); color:var(--muted); font-size:12px;
    font-weight:650; padding:6px 12px; border-radius:8px; cursor:pointer; }
  .btnp:hover { color:var(--ink); border-color:var(--accent); }
  @page { margin: 14mm; }
  @media print {
    /* Force a legible light palette regardless of the on-screen theme, and make
       browsers actually paint severity colors (backgrounds are dropped by default). */
    :root, :root[data-theme="dark"], :root[data-theme="light"] {
      --bg:#fff; --panel:#fff; --panel2:#fff; --ink:#0f1720; --muted:#455; --line:#c9d2dd;
      --accent:#0b7d71; --accent-ink:#fff; --crit:#c0392b; --high:#c05a26; --med:#9a6f16;
      --low:#2f6fb0; --info:#6b7480; --good:#1f7a34; --shadow:none;
    }
    * { -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important; }
    html, body { background:#fff !important; }
    .wrap { max-width:100%; padding:0; }
    /* Hide interactive-only chrome */
    .tabs, .btnp, .actionbar, .selbox { display:none !important; }
    /* Keep cards, traces, and tables intact across page breaks */
    .finding, .card, .fw, .exec, .summary, .cards > *, details, table, tr {
      box-shadow:none !important; break-inside:avoid; page-break-inside:avoid; }
    h2.section, .fh { break-after:avoid; }
    /* Force every <details> (data-flow, remediation plan) fully expanded on paper */
    details > summary { list-style:none; }
    details > summary::before { content:"" !important; }
    details > *:not(summary) { display:block !important; }
    details::details-content { content-visibility:visible !important; display:block !important; }
    a { color:inherit; text-decoration:none; }
  }
  .conf { display:inline-flex; align-items:center; gap:5px; font-size:11px; font-weight:650; color:var(--muted);
    text-transform:capitalize; padding:2px 8px; border:1px solid var(--line); border-radius:20px; white-space:nowrap; }
  .conf .cdot { width:7px; height:7px; border-radius:50%; }
  .flow { margin:10px 0 4px; border:1px solid var(--line); border-radius:9px; background:var(--panel2); overflow:hidden; }
  .flow > summary { cursor:pointer; font-size:12px; font-weight:650; color:var(--ink); padding:8px 12px; list-style:none; }
  .flow > summary::-webkit-details-marker { display:none; }
  .flow > summary::before { content:"▸ "; color:var(--muted); }
  .flow[open] > summary::before { content:"▾ "; }
  .trow { display:flex; align-items:baseline; gap:8px; padding:5px 12px 5px 22px; border-top:1px solid var(--line);
    position:relative; }
  .trow::before { content:""; position:absolute; left:14px; top:0; bottom:0; width:2px; background:var(--line); }
  .trole { font-size:10px; font-weight:750; letter-spacing:.03em; text-transform:uppercase; padding:1px 6px;
    border-radius:5px; color:#fff; white-space:nowrap; flex:none; }
  .trole-source { background:var(--high); } .trole-propagates { background:var(--muted); }
  .trole-tool { background:var(--med); } .trole-sink { background:var(--crit); }
  .tline { color:var(--muted); font-size:11px; flex:none; }
  .tsnip { font-size:11.5px; color:var(--ink); overflow-wrap:anywhere; }

  h2.section { font-size:12px; text-transform:uppercase; letter-spacing:.09em; color:var(--muted);
    margin:32px 0 12px; font-weight:800; }

  .finding { background:var(--panel); border:1px solid var(--line); border-left-width:4px;
    border-radius:12px; padding:15px 17px; margin:11px 0; box-shadow:var(--shadow); }
  .finding.sel { outline:2px solid var(--accent); outline-offset:1px; }
  .fh { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .fh .grow { flex:1; min-width:200px; }
  .selbox { width:17px; height:17px; accent-color:var(--accent); cursor:pointer; flex:none; }
  .sev { font-size:10.5px; font-weight:800; letter-spacing:.05em; padding:3px 7px; border-radius:6px; color:#fff; }
  .title { font-weight:650; }
  .loc { color:var(--muted); font-size:12.5px; }
  .meta { color:var(--muted); font-size:12.5px; margin-top:6px; }
  .kv { margin-top:9px; font-size:13.5px; }
  .kv b { color:var(--muted); font-weight:600; }
  .ev { display:block; margin-top:5px; padding:9px 11px; background:var(--panel2); border:1px solid var(--line);
    border-radius:8px; font-size:12.5px; overflow-x:auto; white-space:pre; }
  .rid { color:var(--muted); font-size:11px; margin-top:9px; }

  .agentbar { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-top:11px;
    padding-top:11px; border-top:1px dashed var(--line); }
  .agent { display:inline-flex; align-items:center; gap:7px; font-size:12.5px; font-weight:650;
    padding:5px 11px; border-radius:999px; background:var(--panel2); border:1px solid var(--line); }
  .agent .gear { color:var(--accent); }
  .mode { font-size:10.5px; font-weight:800; letter-spacing:.04em; padding:3px 8px; border-radius:999px; }
  .mode.auto { background:color-mix(in srgb, var(--good) 16%, transparent); color:var(--good); border:1px solid color-mix(in srgb, var(--good) 40%, transparent); }
  .mode.manual { background:color-mix(in srgb, var(--info) 16%, transparent); color:var(--muted); border:1px solid var(--line); }
  details.plan { margin-top:9px; }
  details.plan summary { cursor:pointer; font-size:12.5px; color:var(--accent); font-weight:650; list-style:none; }
  details.plan summary::-webkit-details-marker { display:none; }
  details.plan summary::before { content:"▸ "; }
  details.plan[open] summary::before { content:"▾ "; }
  details.plan ol { margin:8px 0 2px; padding-left:20px; font-size:13px; color:var(--ink); }
  details.plan li { margin:3px 0; }

  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:12px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; box-shadow:var(--shadow); }
  .card .lab { font-size:11.5px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }
  .card .big { font-size:23px; font-weight:800; letter-spacing:-.02em; margin-top:5px; font-variant-numeric:tabular-nums; }
  .card .note { font-size:12px; color:var(--muted); margin-top:7px; }
  .frameworks { display:flex; flex-direction:column; gap:10px; }
  .fw { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:13px 15px; box-shadow:var(--shadow); }
  .fw .name { font-weight:700; font-size:13px; }
  .fw .ctrls { display:flex; gap:6px; flex-wrap:wrap; margin-top:8px; }
  .pill { font-size:12px; padding:3px 9px; border-radius:999px; background:var(--panel2); border:1px solid var(--line); }

  /* Executive briefing — rendered markdown */
  .exec { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:6px 24px 20px; box-shadow:var(--shadow); }
  .exec h1 { font-size:19px; margin:20px 0 6px; letter-spacing:-.02em; }
  .exec h2 { font-size:14px; text-transform:none; letter-spacing:0; color:var(--ink); margin:20px 0 8px; font-weight:750; }
  .exec h3 { font-size:13px; margin:16px 0 6px; }
  .exec p { font-size:14px; margin:9px 0; }
  .exec ul, .exec ol { font-size:14px; padding-left:22px; margin:9px 0; }
  .exec li { margin:4px 0; }
  .exec strong { font-weight:700; }
  .exec code { background:var(--panel2); border:1px solid var(--line); border-radius:5px; padding:1px 5px; font-size:12.5px; }
  .exec hr { border:none; border-top:1px solid var(--line); margin:16px 0; }
  .exec table { border-collapse:collapse; width:100%; margin:12px 0; font-size:13px; display:block; overflow-x:auto; }
  .exec th, .exec td { border:1px solid var(--line); padding:8px 11px; text-align:left; vertical-align:top; }
  .exec th { background:var(--panel2); font-weight:700; }
  .exec tr:nth-child(even) td { background:color-mix(in srgb, var(--panel2) 55%, transparent); }

  .empty { color:var(--muted); font-size:14px; padding:20px; text-align:center; }
  footer { color:var(--muted); font-size:12px; margin-top:44px; border-top:1px solid var(--line); padding-top:14px; }

  /* Remediation action bar */
  .actionbar { position:fixed; left:50%; transform:translateX(-50%); bottom:18px; max-width:960px; width:calc(100% - 40px);
    background:var(--panel); border:1px solid var(--line); border-radius:14px; box-shadow:0 8px 30px rgba(0,0,0,.22);
    padding:12px 16px; display:none; align-items:center; gap:12px; flex-wrap:wrap; z-index:20; }
  .actionbar.show { display:flex; }
  .actionbar .count { font-weight:750; font-size:13.5px; white-space:nowrap; }
  .actionbar .cmd { flex:1; min-width:220px; font-size:12.5px; background:var(--panel2); border:1px solid var(--line);
    border-radius:8px; padding:8px 10px; overflow-x:auto; white-space:pre; }
  .actionbar label { font-size:12.5px; color:var(--muted); display:inline-flex; align-items:center; gap:6px; cursor:pointer; }
  .btn { border:1px solid var(--accent); background:var(--accent); color:var(--accent-ink); font-weight:700;
    font-size:13px; padding:8px 14px; border-radius:9px; cursor:pointer; white-space:nowrap; }
  .btn.ghost { background:transparent; color:var(--muted); border-color:var(--line); }
  .btn:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }

  @media (max-width:560px){ .summary{ grid-template-columns:1fr; justify-items:center; text-align:center; } }
  @media (prefers-reduced-motion: reduce){ * { transition:none !important; } }
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div>
      <div class="brand">Ortho<span>Sec</span> — AI Security Report</div>
      <div class="target mono">__ROOT__</div>
    </div>
    <div style="display:flex; align-items:center; gap:12px">
      <div class="sub" id="genstamp"></div>
      <button class="btnp" onclick="downloadReport()">Download .html</button>
      <button class="btnp" onclick="printReport()">Print / PDF</button>
    </div>
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
      <div class="sevbar" id="sevbar" aria-hidden="true"></div>
      <div class="meta" id="posture-note" style="margin-top:12px"></div>
    </div>
  </section>

  <div class="owaspwrap"><h2 class="section" style="margin:20px 0 10px">OWASP LLM Top-10 coverage</h2>
    <div class="owasp" id="owaspstrip"></div></div>

  <div id="business"></div>
  <div id="compliance"></div>

  <div id="execWrap" style="display:none">
    <h2 class="section">Executive Briefing</h2>
    <div class="exec" id="exec"></div>
  </div>

  <h2 class="section" id="findings-head">Findings</h2>
  <div id="findings"></div>

  <footer>Generated by OrthoSec · deterministic detectors + grounded intel · <span id="fcount"></span></footer>
</div>

<div class="actionbar" id="actionbar" role="region" aria-label="Remediation">
  <span class="count" id="selcount">0 selected</span>
  <code class="cmd mono" id="cmd"></code>
  <label><input type="checkbox" id="autochk"> auto-fix</label>
  <button class="btn" id="copybtn">Copy command</button>
  <button class="btn ghost" id="clearbtn">Clear</button>
</div>

<script>
const DATA = /*__DATA__*/null;
const SEV_COLOR = { CRITICAL:"var(--crit)", HIGH:"var(--high)", MEDIUM:"var(--med)", LOW:"var(--low)", INFO:"var(--info)" };
const GRADE_COLOR = { A:"var(--good)", B:"var(--good)", C:"var(--med)", D:"var(--high)", F:"var(--crit)" };
const SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
const FLOOR_NAME = ["","INFO","LOW","MEDIUM","HIGH","CRITICAL"];
let current = "__INITIAL_PROFILE__";
const selected = new Set();
const esc = s => String(s==null?"":s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const money = n => "$" + Number(n).toLocaleString("en-US");

/* --- tiny markdown renderer (headings, hr, bold, code, tables, lists, paragraphs) --- */
function inlineMd(s){
  s = esc(s);
  s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>");
  return s;
}
function splitRow(line){ return line.trim().replace(/^\|/,"").replace(/\|$/,"").split("|").map(c=>c.trim()); }
function mdToHtml(md){
  const L = md.replace(/\r/g,"").split("\n"); let out=""; let i=0;
  const isBlank = s=>/^\s*$/.test(s), isH=s=>/^#{1,6}\s/.test(s), isHr=s=>/^\s*([-*_])\1{2,}\s*$/.test(s),
        isRow=s=>/^\s*\|.*\|\s*$/.test(s), isUl=s=>/^\s*[-*]\s+/.test(s), isOl=s=>/^\s*\d+\.\s+/.test(s);
  while(i<L.length){
    const line=L[i];
    if(isBlank(line)){ i++; continue; }
    if(isH(line)){ const m=line.match(/^(#{1,6})\s+(.*)/); out+=`<h${m[1].length}>${inlineMd(m[2])}</h${m[1].length}>`; i++; continue; }
    if(isHr(line)){ out+="<hr>"; i++; continue; }
    if(isRow(line) && i+1<L.length && /-/.test(L[i+1]) && /^\s*\|?[\s:|-]+\|?\s*$/.test(L[i+1])){
      const head=splitRow(line); i+=2; const rows=[];
      while(i<L.length && isRow(L[i])){ rows.push(splitRow(L[i])); i++; }
      out+="<table><thead><tr>"+head.map(c=>`<th>${inlineMd(c)}</th>`).join("")+"</tr></thead><tbody>"+
        rows.map(r=>"<tr>"+r.map(c=>`<td>${inlineMd(c)}</td>`).join("")+"</tr>").join("")+"</tbody></table>"; continue;
    }
    if(isUl(line)){ const it=[]; while(i<L.length&&isUl(L[i])){ it.push(L[i].replace(/^\s*[-*]\s+/,"")); i++; }
      out+="<ul>"+it.map(x=>`<li>${inlineMd(x)}</li>`).join("")+"</ul>"; continue; }
    if(isOl(line)){ const it=[]; while(i<L.length&&isOl(L[i])){ it.push(L[i].replace(/^\s*\d+\.\s+/,"")); i++; }
      out+="<ol>"+it.map(x=>`<li>${inlineMd(x)}</li>`).join("")+"</ol>"; continue; }
    const para=[line]; i++;
    while(i<L.length && !isBlank(L[i]) && !isH(L[i]) && !isHr(L[i]) && !isRow(L[i]) && !isUl(L[i]) && !isOl(L[i])){ para.push(L[i]); i++; }
    out+=`<p>${inlineMd(para.join(" "))}</p>`;
  }
  return out;
}

function renderTabs(){
  const t=document.getElementById("tabs"); t.innerHTML="";
  for(const [id,p] of Object.entries(DATA.profiles)){
    const b=document.createElement("button"); b.className="tab"; b.role="tab"; b.textContent=p.label;
    b.setAttribute("aria-selected", id===current); b.onclick=()=>{ current=id; render(); };
    t.appendChild(b);
  }
}
function renderRing(){
  const r=58, circ=2*Math.PI*r, arc=document.getElementById("arc");
  arc.style.stroke=GRADE_COLOR[DATA.grade]||"var(--accent)";
  arc.setAttribute("stroke-dasharray",circ);
  arc.setAttribute("stroke-dashoffset",circ*(1-DATA.score/100));
  document.getElementById("scoreNum").textContent=DATA.score;
  const g=document.getElementById("gradeTxt"); g.textContent="GRADE "+DATA.grade; g.style.color=GRADE_COLOR[DATA.grade];
}
function renderChips(){
  const c=document.getElementById("sevChips"); c.innerHTML=""; let any=false;
  for(const sev of SEV_ORDER){ const n=DATA.severity_counts[sev]; if(!n) continue; any=true;
    const el=document.createElement("span"); el.className="chip";
    el.innerHTML=`<span class="dot" style="background:${SEV_COLOR[sev]}"></span><span class="n">${n}</span> ${sev.toLowerCase()}`;
    c.appendChild(el); }
  if(!any) c.innerHTML=`<span class="chip"><span class="dot" style="background:var(--good)"></span>No findings — clean scan</span>`;
}
function renderSevBar(){
  const bar=document.getElementById("sevbar"); if(!bar) return; bar.innerHTML="";
  const total=SEV_ORDER.reduce((a,s)=>a+(DATA.severity_counts[s]||0),0);
  if(!total){ bar.innerHTML=`<span style="flex:1;background:var(--good)"></span>`; return; }
  for(const sev of SEV_ORDER){ const n=DATA.severity_counts[sev]||0; if(!n) continue;
    const s=document.createElement("span"); s.style.flex=String(n); s.style.background=SEV_COLOR[sev];
    s.title=`${n} ${sev.toLowerCase()}`; bar.appendChild(s); }
}
const OWASP_IDS = ["LLM01","LLM02","LLM03","LLM04","LLM05","LLM06","LLM07","LLM08","LLM09","LLM10"];
function renderOwasp(){
  const w=document.getElementById("owaspstrip"); if(!w) return; w.innerHTML="";
  const worst={}, cnt={};   // per-category worst severity index + count
  for(const f of DATA.findings){ const id=f.owasp; if(!id) continue;
    cnt[id]=(cnt[id]||0)+1; const si=SEV_ORDER.indexOf(f.severity);
    if(!(id in worst) || si<worst[id]) worst[id]=si; }
  for(const id of OWASP_IDS){ const el=document.createElement("span");
    el.className="ocat"+(cnt[id]?" hit":""); el.title=DATA.owasp_names&&DATA.owasp_names[id]?DATA.owasp_names[id]:id;
    if(cnt[id]){ const sev=SEV_ORDER[worst[id]]; el.style.background=SEV_COLOR[sev];
      el.innerHTML=`${id}<span class="oc-n">${cnt[id]}</span>`; }
    else el.textContent=id;
    w.appendChild(el); }
}
function renderBusiness(p){
  const w=document.getElementById("business"); w.innerHTML="";
  if(!p.show_business) return; const br=DATA.business_risk; const d0=br.risk_drivers[0]||{};
  w.innerHTML=`<h2 class="section">Business Risk</h2><div class="cards">
    <div class="card"><div class="lab">Annualized loss exposure</div>
      <div class="big">${money(br.ale_low_usd)} – ${money(br.ale_high_usd)}</div>
      <div class="note">${esc(br.basis)}</div></div>
    <div class="card"><div class="lab">Top risk driver</div>
      <div class="big" style="font-size:15px;line-height:1.35">${esc(d0.consequence||"—")}</div>
      <div class="note">${esc(d0.owasp||"")} · ${d0.max_severity||""}</div></div></div>`;
}
function renderCompliance(p){
  const w=document.getElementById("compliance"); w.innerHTML="";
  if(!p.show_compliance) return; const c=DATA.compliance; const keys=Object.keys(c); if(!keys.length) return;
  let h=`<h2 class="section">Regulatory Exposure</h2><div class="frameworks">`;
  for(const fw of keys){ const pills=c[fw].map(r=>`<span class="pill" title="${esc(r.description)}">${esc(r.control)}</span>`).join("");
    h+=`<div class="fw"><div class="name">${esc(fw.replace(/_/g," "))}</div><div class="ctrls">${pills}</div></div>`; }
  w.innerHTML=h+"</div>";
}
const CONF = c => c>=0.75 ? {t:"high",c:"var(--good)"} : c>=0.5 ? {t:"medium",c:"var(--med)"} : {t:"low",c:"var(--muted)"};
const ROLE_LABEL = { source:"source", propagates:"flows through", tool:"model-invokable tool", sink:"dangerous sink" };
function traceBlock(f){
  if(!(f.trace||[]).length) return "";
  const rows = f.trace.map(s=>`<div class="trow"><span class="trole trole-${s.role}">${ROLE_LABEL[s.role]||s.role}</span>`+
    `<span class="tline mono">:${s.line}</span><code class="tsnip">${esc(s.snippet||"")}</code></div>`).join("");
  return `<details class="flow" open><summary>Data flow — how tainted data reaches the sink</summary>${rows}</details>`;
}
function findingCard(f, p){
  const checked = selected.has(f.rule_id) ? "checked" : "";
  const mode = f.auto ? `<span class="mode auto">AUTO-FIXABLE</span>` : `<span class="mode manual">MANUAL</span>`;
  const cf = CONF(f.confidence==null?0.8:f.confidence);
  let h=`<div class="finding${selected.has(f.rule_id)?" sel":""}" style="border-left-color:${SEV_COLOR[f.severity]}">
    <div class="fh">
      <input class="selbox" type="checkbox" data-rule="${esc(f.rule_id)}" ${checked} aria-label="Select for remediation">
      <span class="sev" style="background:${SEV_COLOR[f.severity]}">${f.severity}</span>
      <span class="grow"><span class="title">${esc(f.title)}</span></span>
      <span class="conf" title="Detector confidence"><span class="cdot" style="background:${cf.c}"></span>${cf.t}</span>
      <span class="loc mono">${esc(f.location)}</span>
    </div>
    <div class="meta">OWASP ${esc(f.owasp)} (${esc(f.owasp_name)})${f.atlas.length?" · ATLAS "+esc(f.atlas.join(", ")):""}</div>`;
  if(p.show_evidence) h+=traceBlock(f);
  if(p.show_evidence && f.evidence) h+=`<div class="kv"><b>evidence</b><code class="ev">${esc(f.evidence)}</code></div>`;
  if(p.show_business && f.business) h+=`<div class="kv"><b>business:</b> ${esc(f.business)}</div>`;
  if(p.show_remediation) h+=`<div class="kv"><b>fix:</b> ${esc(f.remediation)}</div>`;
  h+=`<div class="agentbar"><span class="agent"><span class="gear">⚙</span>${esc(f.agent)}</span>${mode}</div>`;
  if((f.plan||[]).length) h+=`<details class="plan"><summary>Remediation plan</summary><ol>${
    f.plan.map(s=>`<li>${esc(s)}</li>`).join("")}</ol></details>`;
  h+=`<div class="rid mono">${esc(f.rule_id)}</div></div>`;
  return h;
}
function renderFindings(p){
  const head=document.getElementById("findings-head"), box=document.getElementById("findings"); box.innerHTML="";
  if(!p.show_findings){
    head.textContent="Risk Drivers";
    const d=DATA.business_risk.risk_drivers;
    box.innerHTML=d.map(x=>`<div class="finding" style="border-left-color:${SEV_COLOR[x.max_severity]}">
      <div class="fh"><span class="sev" style="background:${SEV_COLOR[x.max_severity]}">${x.max_severity}</span>
      <span class="title">${esc(x.consequence)}</span></div>
      <div class="meta">${esc(x.owasp)} · ${x.count} finding(s)</div></div>`).join("")
      || `<div class="empty">No findings at or above this profile's threshold.</div>`;
    return;
  }
  head.textContent="Findings & Remediation";
  const shown=DATA.findings.filter(f=>f.sev_value>=p.severity_floor);
  if(!shown.length){ box.innerHTML=`<div class="empty">No findings at or above this profile's threshold.</div>`; return; }
  box.innerHTML=shown.map(f=>findingCard(f,p)).join("");
  const hidden=DATA.findings.length-shown.length;
  if(hidden){ const n=document.createElement("div"); n.className="empty";
    n.textContent=`${hidden} finding(s) below this profile's ${FLOOR_NAME[p.severity_floor]} floor — switch to AI/ML Engineer to see all.`;
    box.appendChild(n); }
  box.querySelectorAll(".selbox").forEach(cb=>cb.addEventListener("change",e=>{
    const id=e.target.dataset.rule; if(e.target.checked) selected.add(id); else selected.delete(id);
    e.target.closest(".finding").classList.toggle("sel", e.target.checked); updateBar();
  }));
}
function updateBar(){
  const bar=document.getElementById("actionbar");
  if(!selected.size){ bar.classList.remove("show"); return; }
  bar.classList.add("show");
  document.getElementById("selcount").textContent=selected.size+" selected";
  const rules=[...selected].join(",");
  const auto=document.getElementById("autochk").checked?" --auto":"";
  document.getElementById("cmd").textContent=`orthosec remediate . --rule ${rules}${auto}`;
}
function render(){
  const p=DATA.profiles[current];
  document.querySelectorAll(".tab").forEach((b,i)=>b.setAttribute("aria-selected", Object.keys(DATA.profiles)[i]===current));
  document.getElementById("audience").textContent="View for "+p.audience+".";
  renderRing(); renderChips(); renderSevBar(); renderOwasp(); renderBusiness(p); renderCompliance(p); renderFindings(p);
  const ew=document.getElementById("execWrap");
  if(DATA.exec_summary){ ew.style.display=""; document.getElementById("exec").innerHTML=mdToHtml(DATA.exec_summary); }
  else ew.style.display="none";
  document.getElementById("posture-note").textContent=
    DATA.findings.length+" finding(s) · "+Object.keys(DATA.compliance).length+" regulatory framework(s) implicated";
  updateBar();
}
document.getElementById("genstamp").textContent="Generated "+DATA.generated;
document.getElementById("fcount").textContent=DATA.findings.length+" findings across all profiles";
document.getElementById("autochk").addEventListener("change",updateBar);
document.getElementById("clearbtn").addEventListener("click",()=>{ selected.clear(); render(); });
document.getElementById("copybtn").addEventListener("click",()=>{
  const txt=document.getElementById("cmd").textContent;
  navigator.clipboard && navigator.clipboard.writeText(txt);
  const b=document.getElementById("copybtn"); b.textContent="Copied ✓"; setTimeout(()=>b.textContent="Copy command",1400);
});
// Build a standalone, self-contained copy of this report (works even inside a
// sandboxed iframe where window.print() is blocked). Strips any injected CSP so the
// saved file's inline CSS/JS run when opened locally.
function _standaloneHtml(){
  _openAllForPrint();                                   // bake details open into the markup
  let html = document.documentElement.outerHTML;
  _restoreAfterPrint();
  html = html.replace(/<meta[^>]+http-equiv=["']?Content-Security-Policy["']?[^>]*>/gi, "");
  return "<!doctype html>\n" + html;
}
function downloadReport(){
  const blob = new Blob([_standaloneHtml()], {type: "text/html"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "orthosec-report.html";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href), 2000);
}
function printReport(){
  const sandboxed = window.self !== window.top;   // inside an artifact iframe?
  if (!sandboxed) { window.print(); return; }      // local file: print dialog works
  // Sandboxed iframe blocks the print dialog — open a standalone tab and print there.
  let w = null;
  try { w = window.open("", "_blank"); } catch(e) {}
  if (w) {
    w.document.write(_standaloneHtml()); w.document.close();
    setTimeout(()=>{ try{ w.focus(); w.print(); }catch(e){} }, 400);
  } else {
    downloadReport();                              // popups blocked: save a printable file
  }
}

// Expand every <details> for printing (data-flow traces + remediation plans), restore after.
let _printOpened = [];
function _openAllForPrint(){
  _printOpened = [];
  document.querySelectorAll("details:not([open])").forEach(d=>{ _printOpened.push(d); d.open=true; });
}
function _restoreAfterPrint(){ _printOpened.forEach(d=>d.open=false); _printOpened=[]; }
window.addEventListener("beforeprint", _openAllForPrint);
window.addEventListener("afterprint", _restoreAfterPrint);
if(window.matchMedia){ const mq=window.matchMedia("print");
  mq.addEventListener && mq.addEventListener("change", e=>{ e.matches ? _openAllForPrint() : _restoreAfterPrint(); }); }

renderTabs(); render();
</script>
</body>
</html>
"""
