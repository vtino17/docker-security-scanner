from typing import List
from .scanner import ScanResult

def generate_report(results: List[ScanResult]) -> str:
    total_checks = sum(len(r.findings) for r in results)
    critical = sum(1 for r in results for f in r.findings if f.severity == "CRITICAL")
    high = sum(1 for r in results for f in r.findings if f.severity == "HIGH")
    medium = sum(1 for r in results for f in r.findings if f.severity == "MEDIUM")
    low = sum(1 for r in results for f in r.findings if f.severity == "LOW")
    passed = sum(1 for r in results for f in r.findings if f.severity == "PASS")
    info = sum(1 for r in results for f in r.findings if f.severity == "INFO")
    unhealthy = sum(1 for r in results if not r.healthy)

    rows = ""
    for scan in results:
        for f in scan.findings:
            rows += f"""<tr>
  <td><span class="severity sev-{f.severity}">{f.severity}</span></td>
  <td>{scan.container_id}</td>
  <td>{f.check}</td>
  <td>{f.status}</td>
  <td>{f.detail}</td>
  <td>{f.recommendation}</td>
</tr>
"""
    now = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Docker Security Scan Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; margin-bottom: 1rem; }}
  h2 {{ color: #f0f6fc; margin: 1.5rem 0 0.5rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat .num {{ font-size: 2rem; font-weight: 700; }}
  .stat .label {{ font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }}
  .crit .num {{ color: #f85149; }} .high .num {{ color: #d29922; }} .med .num {{ color: #db6d28; }}
  .low .num {{ color: #58a6ff; }} .pass .num {{ color: #3fb950; }} .info .num {{ color: #8b949e; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
  th, td {{ padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #21262d; font-size: 0.85rem; }}
  th {{ color: #8b949e; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; background: #161b22; }}
  tr:hover {{ background: #1c2128; }}
  .severity {{ font-weight: 600; }}
  .sev-CRITICAL {{ color: #f85149; }} .sev-HIGH {{ color: #d29922; }}
  .sev-MEDIUM {{ color: #db6d28; }} .sev-LOW {{ color: #58a6ff; }}
  .sev-PASS {{ color: #3fb950; }} .sev-INFO {{ color: #8b949e; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }}
  .badge-healthy {{ background: #1b3d20; color: #3fb950; border: 1px solid #3fb950; }}
  .badge-unhealthy {{ background: #3d1b1b; color: #f85149; border: 1px solid #f85149; }}
</style>
</head>
<body>
<h1>Docker Security Scan Report</h1>
<p style="color: #8b949e;">Generated: {now} &mdash; {unhealthy} of {len(results)} containers unhealthy</p>
<div class="summary">
  <div class="stat"><span class="num">{total_checks}</span><div class="label">Checks</div></div>
  <div class="stat crit"><span class="num">{critical}</span><div class="label">Critical</div></div>
  <div class="stat high"><span class="num">{high}</span><div class="label">High</div></div>
  <div class="stat med"><span class="num">{medium}</span><div class="label">Medium</div></div>
  <div class="stat low"><span class="num">{low}</span><div class="label">Low</div></div>
  <div class="stat pass"><span class="num">{passed}</span><div class="label">Passed</div></div>
  <div class="stat info"><span class="num">{info}</span><div class="label">Info</div></div>
</div>
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Container</th><th>Check</th><th>Status</th><th>Detail</th><th>Recommendation</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"""
