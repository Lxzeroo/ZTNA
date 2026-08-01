"""
Turns logs/access_log.jsonl into a single self-contained dashboard.html --
no external CDN, no server required, just open the file in a browser.

Run after generating some traffic:
    python -m dashboard.generate_dashboard
"""
import html
import json
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.config import ACCESS_LOG_PATH, PROJECT_ROOT

OUT_PATH = os.path.join(PROJECT_ROOT, "dashboard", "dashboard.html")


def load_events():
    if not os.path.exists(ACCESS_LOG_PATH):
        return []
    events = []
    with open(ACCESS_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def build_html(events):
    total = len(events)
    allow = sum(1 for e in events if e.get("decision") == "allow")
    deny = sum(1 for e in events if e.get("decision") == "deny")
    error = sum(1 for e in events if e.get("decision") == "error")

    by_resource = Counter(e.get("resource", "-") for e in events if e.get("event") == "access")
    deny_reasons = Counter(e.get("reason", "-") for e in events if e.get("decision") == "deny")
    by_user = defaultdict(lambda: {"allow": 0, "deny": 0})
    for e in events:
        if e.get("event") == "access" and e.get("username"):
            by_user[e["username"]][e["decision"] if e["decision"] in ("allow", "deny") else "deny"] += 1

    def bar(label, value, max_value, color):
        pct = 0 if max_value == 0 else round(100 * value / max_value)
        return f"""
        <div class="bar-row">
          <div class="bar-label">{html.escape(str(label))}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>
          <div class="bar-value">{value}</div>
        </div>"""

    max_resource = max(by_resource.values(), default=0)
    resource_bars = "".join(
        bar(res, count, max_resource, "#2c4a7c") for res, count in by_resource.most_common()
    )
    max_reason = max(deny_reasons.values(), default=0)
    reason_bars = "".join(
        bar(reason, count, max_reason, "#b23b3b") for reason, count in deny_reasons.most_common()
    )

    rows = []
    for e in reversed(events[-300:]):
        ts = e.get("timestamp_iso", "")
        decision = e.get("decision", "")
        css_class = {"allow": "ok", "deny": "bad", "error": "warn"}.get(decision, "")
        rows.append(
            f"<tr class='{css_class}'>"
            f"<td>{html.escape(ts)}</td>"
            f"<td>{html.escape(str(e.get('event','')))}</td>"
            f"<td>{html.escape(str(e.get('username') or '-'))}</td>"
            f"<td>{html.escape(str(e.get('resource') or '-'))}</td>"
            f"<td>{html.escape(str(e.get('source_ip') or '-'))}</td>"
            f"<td>{html.escape(str(decision))}</td>"
            f"<td>{html.escape(str(e.get('reason') or '-'))}</td>"
            f"<td>{html.escape(str(e.get('device_trust_score') if e.get('device_trust_score') is not None else '-'))}</td>"
            f"</tr>"
        )

    generated_at = time.strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PyZTNA Audit Dashboard</title>
<style>
  :root {{ --navy:#1a2b4c; --muted:#666; --ok:#1e7d34; --bad:#b23b3b; }}
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 0; background:#f5f7fb; color:#222; }}
  header {{ background: var(--navy); color: white; padding: 20px 28px; }}
  header h1 {{ margin: 0 0 4px 0; font-size: 20px; }}
  header p {{ margin: 0; color: #cbd5e8; font-size: 13px; }}
  .wrap {{ padding: 24px 28px; }}
  .cards {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 16px 20px; box-shadow: 0 1px 3px rgba(0,0,0,.08); min-width: 140px; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .lbl {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }}
  .card.ok .num {{ color: var(--ok); }}
  .card.bad .num {{ color: var(--bad); }}
  .panels {{ display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 24px; }}
  .panel {{ background: white; border-radius: 8px; padding: 16px 20px; box-shadow: 0 1px 3px rgba(0,0,0,.08); flex: 1; min-width: 320px; }}
  .panel h2 {{ font-size: 14px; margin: 0 0 12px 0; color: var(--navy); }}
  .bar-row {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: 12px; }}
  .bar-label {{ width: 190px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #444; }}
  .bar-track {{ flex: 1; background: #eef1f7; border-radius: 4px; height: 14px; overflow: hidden; }}
  .bar-fill {{ height: 100%; }}
  .bar-value {{ width: 28px; text-align: right; color: #444; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  th, td {{ text-align: left; padding: 8px 10px; font-size: 12px; border-bottom: 1px solid #eef1f7; }}
  th {{ background: #f0f3fa; color: var(--navy); position: sticky; top: 0; }}
  tr.ok td:nth-child(6) {{ color: var(--ok); font-weight: 600; }}
  tr.bad td:nth-child(6) {{ color: var(--bad); font-weight: 600; }}
  tr.warn td:nth-child(6) {{ color: #a4740a; font-weight: 600; }}
  .tablewrap {{ max-height: 480px; overflow: auto; border-radius: 8px; }}
  footer {{ padding: 16px 28px; color: var(--muted); font-size: 11px; }}
</style>
</head>
<body>
<header>
  <h1>PyZTNA Audit Dashboard</h1>
  <p>Generated {generated_at} &middot; source: logs/access_log.jsonl &middot; {total} events</p>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="num">{total}</div><div class="lbl">Total Events</div></div>
    <div class="card ok"><div class="num">{allow}</div><div class="lbl">Allowed</div></div>
    <div class="card bad"><div class="num">{deny}</div><div class="lbl">Denied</div></div>
    <div class="card"><div class="num">{error}</div><div class="lbl">Backend Errors</div></div>
  </div>
  <div class="panels">
    <div class="panel">
      <h2>Access attempts by resource</h2>
      {resource_bars or '<p style="color:#999;font-size:12px;">No access events yet.</p>'}
    </div>
    <div class="panel">
      <h2>Denial reasons</h2>
      {reason_bars or '<p style="color:#999;font-size:12px;">No denials logged yet.</p>'}
    </div>
  </div>
  <div class="panel" style="margin-bottom:24px;">
    <h2>Recent audit trail (most recent first, up to 300 rows)</h2>
    <div class="tablewrap">
    <table>
      <thead><tr>
        <th>Time</th><th>Event</th><th>User</th><th>Resource</th><th>Source IP</th>
        <th>Decision</th><th>Reason</th><th>Device Trust</th>
      </tr></thead>
      <tbody>
        {''.join(rows) if rows else '<tr><td colspan="8" style="text-align:center;color:#999;">No events logged yet -- run the client agent or the test suite first.</td></tr>'}
      </tbody>
    </table>
    </div>
  </div>
</div>
<footer>PyZTNA classroom project &middot; regenerate with: python -m dashboard.generate_dashboard</footer>
</body>
</html>
"""


def main():
    events = load_events()
    out = build_html(events)
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"Dashboard written to {OUT_PATH} ({len(events)} events)")


if __name__ == "__main__":
    main()
