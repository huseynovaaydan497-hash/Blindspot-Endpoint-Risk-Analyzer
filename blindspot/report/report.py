"""
Risk assessment report -- hackathon requirement 4 ("Produce a structured risk assessment report").

Owner: D

Public interface:
    build_report(results, scope=None) -> dict      structured report (JSON-serialisable)
    render_html(report) -> str                     self-contained HTML, prints cleanly to PDF
    write_report(report, out_dir) -> dict[str, Path]
"""
from __future__ import annotations

import json
from collections import Counter
from html import escape
from pathlib import Path

from blindspot import __version__
from blindspot.analyzer.exposure import load_crown_jewels
from blindspot.contract import LEVEL_THRESHOLDS, now_iso

LEVEL_ORDER = ("high", "medium", "low")
WATCHED = ("broad host access", "cookies", "webRequest")  # named in the hackathon brief


def build_report(results: list[dict], scope: dict | None = None) -> dict:
    results = sorted(results, key=lambda r: r["score"], reverse=True)
    levels = Counter(r["level"] for r in results)
    recs = Counter(r["recommendation"] for r in results)
    flag_counts = Counter(flag for r in results for flag in r.get("high_risk_permissions", []))
    n = len(results)

    summary = {
        "extensions_analyzed": n,
        "by_level": {lvl: levels.get(lvl, 0) for lvl in LEVEL_ORDER},
        "by_recommendation": {k: recs.get(k, 0) for k in ("block", "contain", "review", "allow")}
        | ({"quarantine": recs["quarantine"]} if recs.get("quarantine") else {}),
        "ai_extensions": sum(1 for r in results if (r.get("ai") or {}).get("is_ai")),
        "average_score": round(sum(r["score"] for r in results) / n, 1) if n else 0,
        "high_risk_permission_counts": {flag: flag_counts.get(flag, 0) for flag in WATCHED},
    }

    crown = []
    for system in load_crown_jewels():
        hits = [x for x in results if system["name"] in [e["system"] for e in x.get("exposure", [])]]
        crown.append({"system": system["name"], "hosts": system["hosts"],
                      "extensions": [{"id": x["id"], "name": x["name"], "score": x["score"],
                                      "ai": bool((x.get("ai") or {}).get("is_ai")),
                                      "recommendation": x["recommendation"]} for x in hits]})

    return {
        "report_type": "blindspot.risk_assessment",
        "tool_version": __version__,
        "generated_at": now_iso(),
        "scope": scope or {},
        "summary": summary,
        "executive_summary": _executive_summary(summary, results, crown),
        "crown_jewels": crown,
        "top_risks": [
            {"id": r["id"], "name": r["name"], "score": r["score"], "level": r["level"],
             "recommendation": r["recommendation"],
             "main_reason": r["findings"][0]["title"] if r["findings"] else ""}
            for r in results if r["level"] != "low"
        ][:5],
        "methodology": {
            "method": "OWASP Risk Rating Methodology: Risk = Likelihood x Impact (0-9 factors)",
            "likelihood_factors": ["code", "network", "reputation"],
            "impact_factors": ["technical (permissions)", "business (crown-jewel systems reached)"],
            "combination": "0.6 * strongest factor + 0.4 * average (OWASP step 6 customisation)",
            "severity_matrix": "OWASP step 4: Note / Low / Medium / High / Critical",
            "score_bands": {"Critical": "85-100", "High": "70-84", "Medium": "35-69", "Low": "10-34", "Note": "0-9"},
            "levels": {"high": f">= {LEVEL_THRESHOLDS['high']}",
                       "medium": f">= {LEVEL_THRESHOLDS['medium']}",
                       "low": f"< {LEVEL_THRESHOLDS['medium']}"},
            "attack": "Capabilities mapped to MITRE ATT&CK; every extension is T1176.001 Browser Extensions",
            "references": ["https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
                           "https://attack.mitre.org/techniques/T1176/001/"],
        },
        "extensions": results,
    }


def _executive_summary(summary: dict, results: list[dict], crown: list[dict] | None = None) -> str:
    n = summary["extensions_analyzed"]
    if not n:
        return "No browser extensions were found in the analysed scope."
    high = summary["by_level"]["high"]
    medium = summary["by_level"]["medium"]
    broad = summary["high_risk_permission_counts"]["broad host access"]
    parts = [f"{n} browser extensions were analysed."]
    if high:
        names = ", ".join(r["name"] for r in results if r["level"] == "high")
        parts.append(f"{high} carry high risk and should be blocked: {names}.")
    review = summary["by_recommendation"].get("review", 0)
    if review:
        parts.append(f"{review} {'needs' if review == 1 else 'need'} a manual review.")
    if broad:
        parts.append(f"{broad} can read and change every website the user opens.")
    exposed = [c for c in (crown or []) if c["extensions"]]
    if exposed:
        worst = max(exposed, key=lambda c: len(c["extensions"]))
        parts.append(f"{len(exposed)} critical system(s) can be read by browser extensions; "
                     f"{worst['system']} is reachable by {len(worst['extensions'])} of them.")
    ai = [r for r in results if (r.get("ai") or {}).get("is_ai")]
    if ai:
        parts.append(f"{len(ai)} AI tool(s) were found; "
                     f"{sum(1 for r in ai if r.get('exposure'))} of them can read critical systems.")
    contain = summary["by_recommendation"].get("contain", 0)
    if contain:
        parts.append(f"{contain} extension(s) can stay in use if they are kept off critical systems "
                     "with the generated containment policy.")
    if not high and not medium and not exposed:
        parts.append("No extension requires action.")
    return " ".join(parts)


# ---------------------------------------------------------------- HTML

CSS = """
*{box-sizing:border-box}body{font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1d2433;margin:0;background:#f6f7f9}
main{max-width:960px;margin:0 auto;padding:32px 24px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}
h3{font-size:16px;margin:0}.muted{color:#5b6475}.card{background:#fff;border:1px solid #e3e6eb;border-radius:10px;padding:18px 20px;margin:12px 0}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.tile{background:#fff;border:1px solid #e3e6eb;border-radius:10px;padding:14px}
.tile b{display:block;font-size:26px}.badge{display:inline-block;border-radius:999px;padding:2px 10px;font-weight:600;font-size:12px}
.high{background:#fde8e8;color:#9b1c1c}.medium{background:#fdf3d7;color:#8a5a00}.low{background:#e3f4ea;color:#1e6b3c}
.critical{background:#9b1c1c;color:#fff}.info{background:#eef0f4;color:#5b6475}
table{width:100%;border-collapse:collapse;margin-top:8px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eceef2;vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#5b6475}code{font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;background:#f1f3f6;padding:1px 4px;border-radius:4px;word-break:break-all}
.score{font-size:30px;font-weight:700}.row{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
@media print{body{background:#fff}.card{break-inside:avoid}}
"""


def _badge(text: str, cls: str | None = None) -> str:
    return f'<span class="badge {escape(cls or text)}">{escape(text)}</span>'


def _extension_html(r: dict) -> str:
    perm_rows = "".join(
        f"<tr><td><code>{escape(c['permission'])}</code></td><td>{escape(c['meaning'])}</td></tr>"
        for c in r.get("capabilities", [])
    ) or '<tr><td colspan="2" class="muted">No permissions requested.</td></tr>'
    finding_rows = "".join(
        f"<tr><td>{_badge(f['severity'])}</td><td><b>{escape(f['title'])}</b><br>{escape(f['detail'])}"
        + (f"<br><code>{escape(str(f['evidence']))}</code>" if f.get("evidence") else "")
        + f"</td><td>{f['points']:g}</td></tr>"
        for f in r["findings"] if f["severity"] != "info" or f["signal"] == "score"
    ) or '<tr><td colspan="3" class="muted">No risk findings.</td></tr>'
    unknown = [e for e in r.get("endpoints", []) if not e["known"]]
    endpoints = ", ".join(f"<code>{escape(e['host'])}</code>" for e in unknown) or '<span class="muted">none</span>'
    exposure_text = ", ".join(escape(e["system"]) for e in r.get("exposure", [])) or '<span class="muted">none</span>'
    ai = r.get("ai") or {}
    ai_line = (f"<p><b>AI tool:</b> {escape(', '.join(ai.get('services', [])) or 'identified by name')}</p>"
               if ai.get("is_ai") else "")
    signals = ", ".join(
        f"{name} {s['score']}" + ("" if s["available"] else " (n/a)") for name, s in r["signals"].items()
    )
    rating = r.get("rating") or {}
    rating_line = (f"<div class=\"muted\">OWASP rating: likelihood {rating['likelihood']} ({rating['likelihood_level']}) "
                   f"x impact {rating['impact']} ({rating['impact_level']}) = <b>{escape(rating.get('raw_severity', rating['severity']))}</b>"
                   + (" (capped: approved ID)" if rating.get("capped") else "") + "</div>") if rating else ""
    attack_line = ", ".join(f"{escape(t['id'])} {escape(t['name'])}" for t in r.get("attack", [])[1:])
    attack_line = f"<p><b>MITRE ATT&amp;CK:</b> {attack_line}</p>" if attack_line else ""
    return f"""
<div class="card">
  <div class="row">
    <div><h3>{escape(r['name'])} <span class="muted">{escape(r['version'])}</span></h3>
      <div class="muted"><code>{escape(r['id'])}</code> · Manifest V{r['manifest_version']}</div>
      <div class="muted">Signals: {escape(signals)}</div>{rating_line}</div>
    <div style="text-align:right"><div class="score">{r['score']}</div>{_badge(r['level'])} {_badge(r['recommendation'], 'info')}</div>
  </div>
  <h2 style="font-size:14px;margin:16px 0 4px">What it can do</h2>
  <table><tr><th>Permission</th><th>Meaning</th></tr>{perm_rows}</table>
  <h2 style="font-size:14px;margin:16px 0 4px">Why this score</h2>
  <table><tr><th>Severity</th><th>Finding</th><th>Points</th></tr>{finding_rows}</table>
  <p><b>Unrecognised servers:</b> {endpoints}</p>
  <p><b>Critical systems it can reach:</b> {exposure_text}</p>
  {ai_line}{attack_line}
</div>"""


def render_html(report: dict) -> str:
    s = report["summary"]
    tiles = "".join(
        f'<div class="tile"><span class="muted">{label}</span><b>{value}</b></div>'
        for label, value in (
            ("Extensions analysed", s["extensions_analyzed"]),
            ("High risk", s["by_level"]["high"]),
            ("Need review", s["by_level"]["medium"]),
            ("Average score", s["average_score"]),
        )
    )
    flags = "".join(f"<tr><td>{escape(k)}</td><td>{v}</td></tr>" for k, v in s["high_risk_permission_counts"].items())
    top = "".join(
        f"<tr><td>{escape(t['name'])}</td><td>{t['score']}</td><td>{_badge(t['level'])}</td>"
        f"<td>{escape(t['recommendation'])}</td><td>{escape(t['main_reason'])}</td></tr>"
        for t in report["top_risks"]
    ) or '<tr><td colspan="5" class="muted">No high or medium risk extensions.</td></tr>'
    crown_rows = "".join(
        f"<tr><td><b>{escape(c['system'])}</b><br><code>{escape(', '.join(c['hosts']))}</code></td>"
        f"<td>{len(c['extensions'])}</td><td>{sum(1 for e in c['extensions'] if e['ai'])}</td>"
        f"<td>{escape(', '.join(e['name'] for e in c['extensions'][:6]) or '—')}</td></tr>"
        for c in report.get("crown_jewels", [])
    ) or '<tr><td colspan="4" class="muted">No critical systems configured.</td></tr>'
    scope = report.get("scope") or {}
    scope_text = " · ".join(f"{escape(str(k))}: {escape(str(v))}" for k, v in scope.items())
    body = "".join(_extension_html(r) for r in report["extensions"])
    m = report["methodology"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blindspot Risk Assessment</title><style>{CSS}</style></head>
<body><main>
<h1>Browser Extension Risk Assessment</h1>
<div class="muted">Generated by Blindspot {escape(report['tool_version'])} at {escape(report['generated_at'])}{(' · ' + scope_text) if scope_text else ''}</div>
<h2>Executive summary</h2><div class="card">{escape(report['executive_summary'])}</div>
<div class="tiles">{tiles}</div>
<h2>Top risks</h2><div class="card"><table><tr><th>Extension</th><th>Score</th><th>Level</th><th>Action</th><th>Main reason</th></tr>{top}</table></div>
<h2>Critical systems exposure (blast radius)</h2><div class="card">
<p class="muted">Which extensions could read and change the organisation's most sensitive systems if they turned malicious.</p>
<table><tr><th>System</th><th>Extensions</th><th>AI tools</th><th>Which</th></tr>{crown_rows}</table></div>
<h2>High-risk permissions across the fleet</h2><div class="card"><table><tr><th>Permission</th><th>Extensions</th></tr>{flags}</table></div>
<h2>Extension details</h2>{body}
<h2>Methodology</h2><div class="card">
<p>Ratings follow the <b>OWASP Risk Rating Methodology</b> (Risk = Likelihood &times; Impact, factors on a 0&ndash;9 scale).
Likelihood: malicious-code indicators, unrecognised network destinations and supply-chain reputation.
Impact: what the permissions allow (technical) and how many of the organisation's critical systems the extension reaches (business).
Each side is {escape(m['combination'])}. OWASP's severity matrix gives Note, Low, Medium, High or Critical; the 0&ndash;100 score is that band
(Critical 85&ndash;100, High 70&ndash;84, Medium 35&ndash;69, Low 10&ndash;34, Note 0&ndash;9) refined by likelihood &times; impact.</p>
<p>Levels: high {escape(m['levels']['high'])} (block), medium {escape(m['levels']['medium'])} (review), low {escape(m['levels']['low'])} (allow).
Factors without data are excluded rather than treated as safe; if no likelihood factor can be measured, likelihood is set to medium.
Capabilities are mapped to MITRE ATT&amp;CK (T1176.001 Browser Extensions and follow-on techniques).</p>
<p class="muted">Sources: owasp.org/www-community/OWASP_Risk_Rating_Methodology &middot; attack.mitre.org/techniques/T1176/001</p></div>
</main></body></html>"""


def write_report(report: dict, out_dir) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "report.json"
    html_path = out / "report.html"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    return {"json": json_path, "html": html_path}
