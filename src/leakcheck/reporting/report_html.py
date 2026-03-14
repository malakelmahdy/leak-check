"""
report_html.py - Generate a self-contained HTML report with charts.

Uses the same prototype dark cybersecurity theme:
  --bg: #0b0c10, --panel: #1f2833, --accent: #66fcf1, --accent-2: #45a29e
"""
from __future__ import annotations

import html as html_mod
import json
from pathlib import Path
from typing import Any
from datetime import datetime


def _esc(s: Any) -> str:
    return html_mod.escape(str(s)) if s else ""


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _dig(d: dict[str, Any], path: list[str]) -> Any:
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _badge_class(category: str) -> str:
    mapping = {
        "prompt_injection": "badge-injection",
        "jailbreak": "badge-jailbreak",
        "data_exfil": "badge-leakage",
        "benign": "badge-benign",
    }
    return mapping.get(category, "badge-benign")


def _verdict_color(verdict: str) -> str:
    return {
        "attack_success": "#f44336",
        "attack_attempt": "#ff9800",
        "safe": "#66fcf1",
    }.get(verdict, "#c5c6c7")


def _severity_badge(level: str) -> str:
    colors = {
        "critical": "#f44336",
        "high": "#ff5722",
        "medium": "#ff9800",
        "low": "#66fcf1",
    }
    color = colors.get(level, "#c5c6c7")
    return f'<span class="sev-badge" style="background:rgba({_hex_to_rgb(color)},0.15);color:{color};border:1px solid rgba({_hex_to_rgb(color)},0.4)">{_esc(level.upper())}</span>'


def _hex_to_rgb(hex_color: str) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)  # type: ignore[index]
    return f"{r},{g},{b}"


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------
def write_report_html(
    out_path: Path,
    run_meta: dict[str, Any],
    summary: dict[str, Any],
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # --- Extract metadata ---
    run_id = run_meta.get("run_id") or ""
    created_at = run_meta.get("created_at") or _now_iso()
    campaign = run_meta.get("campaign_name") or _dig(run_meta, ["config", "run", "name"]) or ""
    model = run_meta.get("model") or _dig(run_meta, ["config", "llm", "params", "model"]) or "—"
    sim_model = _dig(run_meta, ["config", "detection", "similarity_model"]) or "—"

    total: int = int(summary.get("total", 0))
    by_cat: dict[str, dict[str, Any]] = dict(summary.get("by_category", {}) or {})
    top_10: list[dict[str, Any]] = list(summary.get("top_10", []) or [])

    # Compute overall stats
    all_successes = sum(c.get("successes", 0) for c in by_cat.values())
    all_attempts = sum(c.get("attempts", 0) for c in by_cat.values())
    all_safes = sum(c.get("safes", 0) for c in by_cat.values())
    overall_success_rate = (all_successes / total * 100) if total else 0
    overall_attempt_rate = (all_attempts / total * 100) if total else 0
    avg_severity = sum(c.get("avg_severity", 0) * c.get("count", 0) for c in by_cat.values()) / total if total else 0

    # Risk score: 0-100, weighted by success + attempt rates
    risk_score = min(100, int(overall_success_rate * 2 + overall_attempt_rate * 0.5 + avg_severity * 8))

    # --- Chart data ---
    categories = list(by_cat.keys())
    cat_labels = json.dumps(categories)
    cat_successes = json.dumps([by_cat[c].get("successes", 0) for c in categories])
    cat_attempts = json.dumps([by_cat[c].get("attempts", 0) for c in categories])
    cat_safes = json.dumps([by_cat[c].get("safes", 0) for c in categories])
    cat_severities = json.dumps([round(by_cat[c].get("avg_severity", 0), 2) for c in categories])

    # --- Top results rows ---
    result_rows: list[str] = []
    for i, r in enumerate(top_10):
        pid = _esc(r.get("prompt_id", ""))
        base = _esc(r.get("base_id", ""))
        cat = r.get("category", "")
        verdict = r.get("verdict", "")
        sev = float(r.get("severity", 0))
        level = r.get("level", "low")
        conf = float(r.get("confidence", 0))
        rules = r.get("rule_hits", [])
        sim = float(r.get("similarity_score", 0))
        resp_sig = r.get("response_signals", [])
        prompt_text: str = _esc(r.get("prompt_text", ""))
        response_text: str = _esc(r.get("response_text", ""))
        latency = r.get("latency_ms", 0)

        prompt_preview = prompt_text[:2000]  # type: ignore[index]
        response_preview = response_text[:2000]  # type: ignore[index]

        result_rows.append(f"""
        <tr class="result-row" onclick="toggleDetail('detail-{i}')">
          <td>{i+1}</td>
          <td><code>{pid}</code></td>
          <td><span class="badge {_badge_class(cat)}">{_esc(cat)}</span></td>
          <td style="color:{_verdict_color(verdict)};font-weight:600">{_esc(verdict)}</td>
          <td>{sev:.2f} {_severity_badge(level)}</td>
          <td>{conf:.0%}</td>
          <td>{', '.join(_esc(rule) for rule in rules) or '—'}</td>
        </tr>
        <tr id="detail-{i}" class="detail-row" style="display:none">
          <td colspan="7">
            <div class="detail-grid">
              <div class="detail-card">
                <h4>Prompt</h4>
                <pre>{prompt_preview}</pre>
              </div>
              <div class="detail-card">
                <h4>LLM Response</h4>
                <pre>{response_preview}</pre>
              </div>
              <div class="detail-meta">
                <span>Similarity: <strong>{sim:.4f}</strong></span>
                <span>Latency: <strong>{latency}ms</strong></span>
                <span>Response signals: <strong>{', '.join(_esc(s) for s in resp_sig) or '—'}</strong></span>
              </div>
            </div>
          </td>
        </tr>""")

    rows_html = "\n".join(result_rows)

    # --- Over-refusal section ---
    over_refusal_cases: list[dict[str, Any]] = list(summary.get("over_refusal_cases", []) or [])
    total_over_refusals = len(over_refusal_cases)
    over_refusal_html = ""
    if total_over_refusals > 0:
        or_rows: list[str] = []
        for orc in over_refusal_cases:
            or_pid = _esc(str(orc.get("prompt_id", "")))
            or_cat = _esc(str(orc.get("category", "")))
            or_prompt: str = _esc(str(orc.get("prompt_text", "")))
            or_response: str = _esc(str(orc.get("response_text", "")))
            or_prompt_preview = or_prompt[:500]  # type: ignore[index]
            or_response_preview = or_response[:500]  # type: ignore[index]
            or_note = str(orc.get("evidence", {}).get("over_refusal_note", ""))
            or_rows.append(f"""
          <div style="background:#1a1a2e;border:1px solid rgba(255,152,0,0.3);border-radius:12px;padding:1.2rem;margin-bottom:1rem">
            <div style="display:flex;gap:0.6rem;align-items:center;margin-bottom:0.6rem">
              <span style="background:rgba(255,152,0,0.15);color:#ff9800;border:1px solid rgba(255,152,0,0.4);border-radius:20px;padding:2px 10px;font-size:0.75rem;font-weight:600">OVER-REFUSAL</span>
              <code style="color:#66fcf1;font-size:0.8rem">{or_pid}</code>
              <span style="color:#888;font-size:0.8rem">{or_cat}</span>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:0.8rem">
              <div>
                <div style="color:#66fcf1;font-size:0.7rem;font-weight:600;margin-bottom:4px">PROMPT</div>
                <pre style="background:#0d0d1a;padding:0.6rem;border-radius:6px;font-size:0.75rem;max-height:120px;overflow:auto;white-space:pre-wrap;color:#c5c6c7">{or_prompt_preview}</pre>
              </div>
              <div>
                <div style="color:#ff9800;font-size:0.7rem;font-weight:600;margin-bottom:4px">LLM RESPONSE (REFUSAL)</div>
                <pre style="background:#0d0d1a;padding:0.6rem;border-radius:6px;font-size:0.75rem;max-height:120px;overflow:auto;white-space:pre-wrap;color:#c5c6c7">{or_response_preview}</pre>
              </div>
            </div>
            <div style="background:rgba(255,152,0,0.08);border-left:3px solid #ff9800;padding:0.6rem 0.8rem;border-radius:0 6px 6px 0;font-size:0.78rem;color:#ccc;line-height:1.5">
              ⚠️ {_esc(or_note)}
            </div>
          </div>""")
        over_refusal_html = f"""
  <h2 class="section-title" style="color:#ff9800">⚠️ Over-Refusal Findings ({total_over_refusals})</h2>
  <p style="color:#999;font-size:0.85rem;margin-bottom:1rem">
    These prompts contain <strong>no attack patterns</strong> but were <strong>refused by the LLM</strong>.
    This indicates the model's safety filters are being overly cautious, rejecting benign or benign-mutated inputs.
  </p>
  {''.join(or_rows)}
"""

    # --- SVG gauge ---
    gauge_offset = 314 - (314 * risk_score / 100)
    if risk_score >= 70:
        gauge_color = "#f44336"
    elif risk_score >= 40:
        gauge_color = "#ff9800"
    else:
        gauge_color = "#66fcf1"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LeakCheck Report — {_esc(run_id)}</title>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
/* === Reset + Base === */
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{
  --bg:#0b0c10;--panel:#1f2833;--muted:#c5c6c7;
  --accent:#66fcf1;--accent-2:#45a29e;
  --glass:rgba(255,255,255,0.04);
}}
body{{
  font-family:'Poppins',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  background:linear-gradient(180deg,var(--bg) 0%,#071017 100%);
  color:var(--muted);-webkit-font-smoothing:antialiased;
  min-height:100vh;
}}
.container{{max-width:1200px;margin:0 auto;padding:2rem 1.5rem}}

/* === Header === */
.report-header{{
  text-align:center;padding:3rem 0 2rem;
  border-bottom:1px solid rgba(102,252,241,0.1);margin-bottom:2rem;
}}
.logo{{font-size:2rem;font-weight:700;color:var(--accent);letter-spacing:1px}}
.logo span{{color:var(--accent-2)}}
.report-header .meta{{color:var(--muted);font-size:0.9rem;margin-top:0.5rem;opacity:0.8}}
.report-header .meta code{{
  background:rgba(102,252,241,0.08);padding:2px 8px;border-radius:4px;
  font-size:0.85rem;color:var(--accent)
}}

/* === Stat Cards === */
.stat-grid{{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:1.5rem;margin-bottom:2.5rem;
}}
.stat-card{{
  background:var(--panel);border-radius:16px;padding:2rem 1.5rem;
  box-shadow:0 0 25px rgba(102,252,241,0.06);text-align:center;
  transition:transform 0.3s,box-shadow 0.3s;
}}
.stat-card:hover{{transform:translateY(-6px);box-shadow:0 0 35px rgba(102,252,241,0.15)}}
.stat-card .value{{font-size:2.2rem;font-weight:700;color:var(--accent);margin-bottom:0.3rem}}
.stat-card .label{{font-size:0.9rem;color:var(--muted);text-transform:uppercase;letter-spacing:1px}}

/* === Section titles === */
.section-title{{
  color:var(--accent);font-size:1.5rem;font-weight:600;
  margin:2.5rem 0 1.2rem;letter-spacing:0.5px;
  border-left:4px solid var(--accent-2);padding-left:12px;
}}

/* === Chart containers === */
.chart-grid{{
  display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2.5rem;
}}
@media(max-width:768px){{.chart-grid{{grid-template-columns:1fr}}}}
.chart-panel{{
  background:var(--panel);border-radius:16px;padding:1.5rem;
  box-shadow:0 0 20px rgba(102,252,241,0.06);
}}
.chart-panel canvas{{max-height:320px}}

/* === Risk gauge === */
.gauge-section{{
  display:flex;align-items:center;justify-content:center;gap:3rem;
  margin-bottom:2.5rem;flex-wrap:wrap;
}}
.risk-gauge{{width:180px;height:180px;position:relative}}
.gauge{{width:100%;height:100%;transform:rotate(-90deg)}}
.gauge-bg{{fill:none;stroke:rgba(255,255,255,0.1);stroke-width:12}}
.gauge-progress{{
  fill:none;stroke-width:12;stroke-linecap:round;
  stroke-dasharray:314;transition:stroke-dashoffset 1.2s ease-out;
}}
.gauge-text{{
  font-size:1.8rem;font-weight:700;dominant-baseline:middle;
  transform:rotate(90deg);
}}
.gauge-label{{text-align:center;margin-top:0.5rem;font-size:0.9rem;color:var(--muted)}}
.gauge-meta{{font-size:1rem;line-height:2}}
.gauge-meta strong{{color:var(--accent)}}

/* === Results table === */
.results-table{{
  width:100%;border-collapse:collapse;margin-bottom:2rem;
}}
.results-table th{{
  text-align:left;padding:12px 10px;color:var(--accent);
  border-bottom:2px solid rgba(102,252,241,0.2);font-size:0.85rem;
  text-transform:uppercase;letter-spacing:1px;
}}
.results-table td{{
  padding:10px;border-bottom:1px solid rgba(255,255,255,0.05);
  font-size:0.9rem;
}}
.result-row{{cursor:pointer;transition:background 0.2s}}
.result-row:hover{{background:rgba(102,252,241,0.04)}}
.result-row td code{{
  background:rgba(102,252,241,0.08);padding:2px 6px;border-radius:4px;
  font-size:0.85rem;color:var(--accent);
}}

/* === Badges === */
.badge{{
  display:inline-block;padding:4px 10px;border-radius:6px;
  font-weight:600;font-size:0.8rem;letter-spacing:0.3px;
}}
.badge-injection{{background:rgba(255,152,0,0.15);color:#ff9800;border:1px solid rgba(255,152,0,0.3)}}
.badge-jailbreak{{background:rgba(244,67,54,0.15);color:#f44336;border:1px solid rgba(244,67,54,0.3)}}
.badge-leakage{{background:rgba(255,193,7,0.15);color:#ffc107;border:1px solid rgba(255,193,7,0.3)}}
.badge-benign{{background:rgba(102,252,241,0.1);color:#66fcf1;border:1px solid rgba(102,252,241,0.2)}}
.sev-badge{{
  display:inline-block;padding:2px 8px;border-radius:4px;
  font-weight:600;font-size:0.75rem;margin-left:6px;
}}

/* === Detail row === */
.detail-row td{{background:rgba(15,22,32,0.9);padding:0 !important}}
.detail-grid{{padding:1.5rem;display:grid;grid-template-columns:1fr 1fr;gap:1rem}}
@media(max-width:768px){{.detail-grid{{grid-template-columns:1fr}}}}
.detail-card{{
  background:var(--bg);border-radius:10px;padding:1rem;
  border:1px solid rgba(255,255,255,0.05);
}}
.detail-card h4{{color:var(--accent-2);margin-bottom:0.5rem;font-size:0.85rem;text-transform:uppercase}}
.detail-card pre{{
  white-space:pre-wrap;word-break:break-word;font-size:0.82rem;
  color:var(--muted);line-height:1.5;max-height:300px;overflow-y:auto;
}}
.detail-meta{{
  grid-column:1/-1;display:flex;gap:2rem;flex-wrap:wrap;
  padding:0.5rem 0;font-size:0.85rem;
}}
.detail-meta strong{{color:var(--accent)}}

/* === Footer === */
.report-footer{{
  text-align:center;padding:2rem 0;margin-top:2rem;
  border-top:1px solid rgba(255,255,255,0.05);
  font-size:0.85rem;color:#888;
}}

/* === Animations === */
@keyframes fadeUp{{from{{opacity:0;transform:translateY(20px)}}to{{opacity:1;transform:translateY(0)}}}}
.stat-card,.chart-panel{{animation:fadeUp 0.7s ease both}}
.stat-card:nth-child(2){{animation-delay:0.1s}}
.stat-card:nth-child(3){{animation-delay:0.2s}}
.stat-card:nth-child(4){{animation-delay:0.3s}}
.stat-card:nth-child(5){{animation-delay:0.4s}}

/* === Scrollbar === */
::-webkit-scrollbar{{width:8px}}
::-webkit-scrollbar-thumb{{background:var(--accent-2);border-radius:10px}}
::-webkit-scrollbar-track{{background:var(--panel)}}

/* === Print === */
@media print{{
  body{{background:#fff;color:#333}}
  .stat-card,.chart-panel,.detail-card{{box-shadow:none;border:1px solid #ddd}}
  .badge,.sev-badge{{border:1px solid #999}}
}}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="report-header">
    <div class="logo">Leak<span>Check</span></div>
    <h1 style="color:var(--muted);font-size:1.1rem;font-weight:400;margin-top:0.5rem">
      Security Assessment Report
    </h1>
    <div class="meta">
      Run <code>{_esc(run_id)}</code> &middot; {_esc(created_at)} &middot;
      Campaign <code>{_esc(campaign)}</code> &middot;
      Model <code>{_esc(model)}</code>
    </div>
  </div>

  <!-- Stat Cards -->
  <div class="stat-grid">
    <div class="stat-card">
      <div class="value">{total}</div>
      <div class="label">Total Prompts</div>
    </div>
    <div class="stat-card">
      <div class="value" style="color:#f44336">{all_successes}</div>
      <div class="label">Attacks Succeeded</div>
    </div>
    <div class="stat-card">
      <div class="value" style="color:#ff9800">{all_attempts}</div>
      <div class="label">Attacks Attempted</div>
    </div>
    <div class="stat-card">
      <div class="value" style="color:#66fcf1">{all_safes}</div>
      <div class="label">Safe</div>
    </div>
    <div class="stat-card">
      <div class="value">{avg_severity:.1f}</div>
      <div class="label">Avg Severity</div>
    </div>
  </div>

  <!-- Risk Gauge + Charts -->
  <h2 class="section-title">Risk Overview</h2>
  <div class="gauge-section">
    <div>
      <div class="risk-gauge">
        <svg class="gauge" viewBox="0 0 120 120">
          <circle class="gauge-bg" cx="60" cy="60" r="50"/>
          <circle class="gauge-progress" cx="60" cy="60" r="50"
                  style="stroke:{gauge_color};stroke-dashoffset:{gauge_offset}"/>
          <text class="gauge-text" x="60" y="60" text-anchor="middle"
                style="fill:{gauge_color}">{risk_score}</text>
        </svg>
      </div>
      <div class="gauge-label">Risk Score</div>
    </div>
    <div class="gauge-meta">
      <div>Success Rate: <strong>{overall_success_rate:.1f}%</strong></div>
      <div>Attempt Rate: <strong>{overall_attempt_rate:.1f}%</strong></div>
      <div>Avg Severity: <strong>{avg_severity:.2f}</strong></div>
      <div>Similarity Model: <strong>{_esc(sim_model)}</strong></div>
    </div>
  </div>

  <!-- Charts -->
  <h2 class="section-title">Category Breakdown</h2>
  <div class="chart-grid">
    <div class="chart-panel">
      <canvas id="verdictChart"></canvas>
    </div>
    <div class="chart-panel">
      <canvas id="severityChart"></canvas>
    </div>
  </div>

  <!-- Top Results -->
  <h2 class="section-title">Top Results by Severity</h2>
  <div style="overflow-x:auto">
    <table class="results-table">
      <thead>
        <tr>
          <th>#</th><th>Prompt ID</th><th>Category</th><th>Verdict</th>
          <th>Severity</th><th>Confidence</th><th>Rule Hits</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>
  <p style="font-size:0.8rem;color:#666;margin-bottom:2rem">
    Click a row to expand prompt &amp; response details.
  </p>

  {over_refusal_html}

  <!-- Footer -->
  <div class="report-footer">
    Generated by <strong>LeakCheck</strong> &middot; {_esc(created_at)}
  </div>
</div>

<script>
// Toggle detail rows
function toggleDetail(id) {{
  const row = document.getElementById(id);
  if (row) row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}}

// Chart.js defaults
Chart.defaults.color = '#c5c6c7';
Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family = "'Poppins', sans-serif";

// Verdict Distribution
new Chart(document.getElementById('verdictChart'), {{
  type: 'bar',
  data: {{
    labels: {cat_labels},
    datasets: [
      {{label:'Succeeded', data:{cat_successes}, backgroundColor:'rgba(244,67,54,0.7)', borderRadius:6}},
      {{label:'Attempted', data:{cat_attempts}, backgroundColor:'rgba(255,152,0,0.7)', borderRadius:6}},
      {{label:'Safe',      data:{cat_safes},     backgroundColor:'rgba(102,252,241,0.5)', borderRadius:6}},
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{
      title: {{display:true, text:'Verdict Distribution by Category', color:'#66fcf1', font:{{size:14}}}},
      legend: {{position:'bottom'}}
    }},
    scales: {{
      x: {{grid:{{display:false}}}},
      y: {{beginAtZero:true, ticks:{{stepSize:1}}}}
    }}
  }}
}});

// Severity by Category
new Chart(document.getElementById('severityChart'), {{
  type: 'bar',
  data: {{
    labels: {cat_labels},
    datasets: [{{
      label: 'Avg Severity',
      data: {cat_severities},
      backgroundColor: {cat_labels}.map((_,i) =>
        ['rgba(255,152,0,0.7)','rgba(244,67,54,0.7)','rgba(255,193,7,0.7)','rgba(102,252,241,0.5)'][i % 4]
      ),
      borderRadius: 6,
    }}]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true,
    plugins: {{
      title: {{display:true, text:'Average Severity by Category', color:'#66fcf1', font:{{size:14}}}},
      legend: {{display:false}}
    }},
    scales: {{
      x: {{beginAtZero:true, max:10, grid:{{color:'rgba(255,255,255,0.04)'}}}},
      y: {{grid:{{display:false}}}}
    }}
  }}
}});
</script>
</body>
</html>"""

    out_path.write_text(html, encoding="utf-8")
