from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any


def _txt(value: Any) -> str:
    return "" if value is None else str(value)


def _esc(value: Any) -> str:
    return html.escape(_txt(value))


def write_proxy_report_md(out_path: str | Path, payload: dict[str, Any]) -> Path:
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    session = dict(payload.get("session", {}) or {})
    findings = list(payload.get("findings", []) or [])
    exchanges = list(payload.get("exchanges", []) or [])
    replay_results = list(payload.get("replay_results", []) or [])
    scoring = dict(payload.get("scoring", {}) or {})
    certificate = dict(session.get("certificate", {}) or {})

    lines = [
        "# LeakCheck Proxy Capture Report",
        "",
        "## Session",
        f"- Session ID: `{session.get('session_id', '')}`",
        f"- Status: `{session.get('status', '')}`",
        f"- Capture mode: `{session.get('capture_mode', session.get('mode', ''))}`",
        f"- Target URL: `{session.get('target_url', '')}`",
        f"- Listen URL: `{session.get('listen_url', '')}`",
        f"- Started at: `{session.get('started_at', '')}`",
        f"- Stopped at: `{session.get('stopped_at', '')}`",
        f"- Exchange count: **{len(exchanges)}**",
        f"- Finding count: **{len(findings)}**",
        f"- Scored turns: **{scoring.get('turn_count', len(findings))}**",
        f"- Worst leak severity: **{float(scoring.get('worst_leak_severity', 0.0)):.1f}**",
        f"- Worst attack risk: **{float(scoring.get('worst_attack_risk', 0.0)):.1f}**",
        "",
        "## Security Controls",
        "- Header tokens are redacted in captures and exports.",
        "- Body redaction depends on the export mode used to generate this report.",
        "- Active injection records, when present, are marked in exchange metadata and audit logs.",
    ]
    if certificate:
        lines.extend(
            [
                "- Browser proxy certificates are never auto-installed by LeakCheck.",
                f"- Certificate directory: `{certificate.get('cert_dir', '')}`",
                f"- CA generated: `{bool(certificate.get('generated', False))}`",
                "- HTTPS decrypted: `False`",
            ]
        )
        if certificate.get("generation_error"):
            lines.append(f"- Certificate generation note: `{certificate.get('generation_error')}`")
    lines.extend(["", "## Findings"])

    if not findings:
        lines.append("No scored prompt/response findings were extracted.")
    for finding in findings:
        detection = dict(finding.get("detection", {}) or {})
        lines.extend(
            [
                f"### Turn {finding.get('turn_number', '')}",
                f"- Exchange ID: `{finding.get('exchange_id', '')}`",
                f"- Verdict: `{detection.get('verdict', '')}`",
                f"- Attack risk: `{float(detection.get('attack_risk_score', 0.0)):.2f}` ({detection.get('attack_risk_band', 'none')})",
                f"- Leak severity: `{float(detection.get('signoff_severity', detection.get('severity', 0.0))):.2f}` ({detection.get('signoff_severity_label', detection.get('level', 'none'))})",
                f"- Rule hits: `{', '.join(str(item) for item in detection.get('rule_hits', []) or [])}`",
                "",
                "Prompt:",
                "```text",
                _txt(finding.get("prompt_text", ""))[:2000],
                "```",
                "Response:",
                "```text",
                _txt(finding.get("response_text", ""))[:2000],
                "```",
                "",
            ]
        )

    if replay_results:
        lines.extend(["## Replay Results", ""])
        for item in replay_results:
            comparison = dict(item.get("comparison", {}) or {})
            lines.append(
                f"- `{comparison.get('exchange_id', '')}` status_match={comparison.get('status_matches')} "
                f"exact_match={comparison.get('response_matches_exactly')} "
                f"original_status={comparison.get('original_status')} replay_status={comparison.get('replay_status')}"
            )

    stream_rows = [
        exchange
        for exchange in exchanges
        if isinstance(exchange, dict) and dict(exchange.get("metadata", {}) or {}).get("stream_reconstruction")
    ]
    if stream_rows:
        lines.extend(["", "## Stream Reconstruction", ""])
        for exchange in stream_rows:
            metadata = dict(dict(exchange.get("metadata", {}) or {}).get("stream_reconstruction", {}) or {})
            lines.append(
                f"- `{exchange.get('exchange_id', '')}` format=`{metadata.get('stream_format', '')}` "
                f"chunks=`{metadata.get('chunk_count', 0)}` confidence=`{metadata.get('confidence', 0.0)}`"
            )

    target.write_text("\n".join(lines), encoding="utf-8")
    return target


def write_proxy_report_html(out_path: str | Path, payload: dict[str, Any]) -> Path:
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    session = dict(payload.get("session", {}) or {})
    findings = list(payload.get("findings", []) or [])
    exchanges = list(payload.get("exchanges", []) or [])
    replay_results = list(payload.get("replay_results", []) or [])
    scoring = dict(payload.get("scoring", {}) or {})
    certificate = dict(session.get("certificate", {}) or {})

    finding_cards = []
    for finding in findings:
        detection = dict(finding.get("detection", {}) or {})
        finding_cards.append(
            f"""
            <article class="finding">
              <header>
                <strong>Turn {_esc(finding.get('turn_number', ''))}</strong>
                <span>{_esc(detection.get('verdict', ''))}</span>
              </header>
              <div class="metrics">
                <div>Attack Risk <b>{float(detection.get('attack_risk_score', 0.0)):.2f}</b></div>
                <div>Leak Severity <b>{float(detection.get('signoff_severity', detection.get('severity', 0.0))):.2f}</b></div>
                <div>Rules <b>{_esc(', '.join(str(item) for item in detection.get('rule_hits', []) or []))}</b></div>
              </div>
              <div class="chain">
                <section><h3>Prompt</h3><pre>{_esc(_txt(finding.get('prompt_text', ''))[:3000])}</pre></section>
                <section><h3>Response</h3><pre>{_esc(_txt(finding.get('response_text', ''))[:3000])}</pre></section>
              </div>
            </article>
            """
        )

    replay_rows = []
    for item in replay_results:
        comparison = dict(item.get("comparison", {}) or {})
        replay_rows.append(
            f"<tr><td>{_esc(comparison.get('exchange_id', ''))}</td>"
            f"<td>{_esc(comparison.get('status_matches', ''))}</td>"
            f"<td>{_esc(comparison.get('response_matches_exactly', ''))}</td>"
            f"<td>{_esc(comparison.get('original_status', ''))}</td>"
            f"<td>{_esc(comparison.get('replay_status', ''))}</td></tr>"
        )

    stream_rows = []
    for exchange in exchanges:
        if not isinstance(exchange, dict):
            continue
        metadata = dict(dict(exchange.get("metadata", {}) or {}).get("stream_reconstruction", {}) or {})
        if not metadata:
            continue
        stream_rows.append(
            f"<tr><td>{_esc(exchange.get('exchange_id', ''))}</td>"
            f"<td>{_esc(metadata.get('stream_format', ''))}</td>"
            f"<td>{_esc(metadata.get('chunk_count', ''))}</td>"
            f"<td>{_esc(metadata.get('confidence', ''))}</td></tr>"
        )

    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LeakCheck Proxy Report - {_esc(session.get('session_id', ''))}</title>
  <style>
    body{{margin:0;background:#0b0c10;color:#c5c6c7;font-family:system-ui,-apple-system,Segoe UI,sans-serif}}
    main{{max-width:1180px;margin:0 auto;padding:32px 20px}}
    h1,h2{{color:#66fcf1}}
    .summary,.notice,.finding{{background:#1f2833;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px;margin:16px 0}}
    .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
    .summary div{{background:#0f1620;border-radius:8px;padding:12px}}
    .finding header{{display:flex;justify-content:space-between;gap:12px;color:#fff;margin-bottom:12px}}
    .metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-bottom:12px}}
    .metrics div{{background:#0f1620;border-radius:8px;padding:10px}}
    .metrics b{{color:#66fcf1}}
    .chain{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
    @media(max-width:800px){{.chain{{grid-template-columns:1fr}}}}
    pre{{white-space:pre-wrap;word-break:break-word;background:#0b0c10;border-radius:8px;padding:12px;max-height:360px;overflow:auto}}
    table{{width:100%;border-collapse:collapse;background:#1f2833;border-radius:8px;overflow:hidden}}
    th,td{{text-align:left;border-bottom:1px solid rgba(255,255,255,.06);padding:10px}}
    th{{color:#66fcf1;background:#0f1620}}
  </style>
</head>
<body>
<main>
  <h1>LeakCheck Proxy Capture Report</h1>
  <p>Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
  <section class="summary">
    <div><strong>Session</strong><br>{_esc(session.get('session_id', ''))}</div>
    <div><strong>Status</strong><br>{_esc(session.get('status', ''))}</div>
    <div><strong>Capture Mode</strong><br>{_esc(session.get('capture_mode', session.get('mode', '')))}</div>
    <div><strong>Target</strong><br>{_esc(session.get('target_url', ''))}</div>
    <div><strong>Listen URL</strong><br>{_esc(session.get('listen_url', ''))}</div>
    <div><strong>Exchanges</strong><br>{len(exchanges)}</div>
    <div><strong>Findings</strong><br>{len(findings)}</div>
    <div><strong>Scored Turns</strong><br>{_esc(scoring.get('turn_count', len(findings)))}</div>
    <div><strong>Worst Leak</strong><br>{float(scoring.get('worst_leak_severity', 0.0)):.1f}</div>
    <div><strong>Worst Attack</strong><br>{float(scoring.get('worst_attack_risk', 0.0)):.1f}</div>
  </section>
  <section class="notice">
    <h2>Security Controls</h2>
    <p>Header tokens are redacted. Body redaction depends on the export mode used to generate this report.</p>
    {"<p>Browser proxy certificates are never auto-installed by LeakCheck. HTTPS decrypted: <b>False</b>.</p>" if certificate else ""}
    {f"<p>Certificate directory: <code>{_esc(certificate.get('cert_dir', ''))}</code></p>" if certificate else ""}
    {f"<p>Certificate note: {_esc(certificate.get('generation_error', ''))}</p>" if certificate.get('generation_error') else ""}
  </section>
  <h2>Findings</h2>
  {''.join(finding_cards) if finding_cards else '<p>No scored prompt/response findings were extracted.</p>'}
  <h2>Replay Results</h2>
  <table>
    <thead><tr><th>Exchange</th><th>Status Match</th><th>Exact Match</th><th>Original</th><th>Replay</th></tr></thead>
    <tbody>{''.join(replay_rows) if replay_rows else '<tr><td colspan="5">No replay results.</td></tr>'}</tbody>
  </table>
  <h2>Stream Reconstruction</h2>
  <table>
    <thead><tr><th>Exchange</th><th>Format</th><th>Chunks</th><th>Confidence</th></tr></thead>
    <tbody>{''.join(stream_rows) if stream_rows else '<tr><td colspan="4">No reconstructed streams.</td></tr>'}</tbody>
  </table>
</main>
</body>
</html>"""
    target.write_text(body, encoding="utf-8")
    return target
