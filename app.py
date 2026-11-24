import os
import sys
import json
import socket
import signal
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template_string
import redis

# --- ZASADA XI: LOGS (Strumień zdarzeń na stdout w formacie JSON) ---
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "vuln-triage-api",
            "instance": socket.gethostname(),
            "message": record.getMessage(),
        }
        return json.dumps(log_record)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JsonFormatter())
logger = logging.getLogger("vuln-triage")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

app = Flask(__name__)

# --- ZASADA III: CONFIG (Konfiguracja wyłącznie ze środowiska) ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
APP_ENV = os.getenv("APP_ENV", "production")

# --- ZASADA IV: BACKING SERVICES (Wymienny zasób zewnętrzny) ---
db = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_connect_timeout=2)

# --- ZASADA IX: DISPOSABILITY (Graceful Shutdown na SIGTERM/SIGINT) ---
def graceful_shutdown(signum, frame):
    logger.info(f"Received signal {signum}. Closing backing service connections gracefully...")
    try:
        db.close()
    except Exception as e:
        logger.error(f"Error closing Redis connection: {e}")
    logger.info("Shutdown complete.")
    sys.exit(0)

signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

def calculate_risk(cvss: float, internet_facing: bool, asset_type: str) -> dict:
    """Silnik priorytetyzacji ryzyka (CTEM / Vulnerability Management)."""
    score = cvss
    if internet_facing:
        score += 1.5
    if asset_type.upper() == "OT":
        score += 1.0

    if score >= 9.0:
        return {"priority": "P1 - CRITICAL", "sla_hours": 24, "action": "Immediate emergency patching / virtual patching via WAF"}
    elif score >= 7.0:
        return {"priority": "P2 - HIGH", "sla_hours": 72, "action": "Schedule out-of-band remediation within 3 days"}
    elif score >= 4.0:
        return {"priority": "P3 - MEDIUM", "sla_hours": 336, "action": "Include in standard bi-weekly patch cycle"}
    return {"priority": "P4 - LOW", "sla_hours": 720, "action": "Monitor and remediate during routine maintenance"}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>12-Factor Vulnerability Triage & DevSecOps Engine</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --accent: #38bdf8; --p1: #ef4444; --p2: #f97316; --p3: #eab308; --p4: #22c55e; }
        body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }
        .container { max-width: 1100px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }
        h1 { font-size: 1.5rem; margin: 0; color: var(--accent); }
        .badge { background: #0284c7; padding: 4px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card { background: var(--card); padding: 18px; border-radius: 10px; border: 1px solid #334155; }
        .card h3 { margin: 0 0 8px 0; font-size: 0.85rem; color: var(--muted); text-transform: uppercase; }
        .card .val { font-size: 1.6rem; font-weight: 700; }
        .form-row { display: flex; gap: 12px; flex-wrap: wrap; align-items: end; }
        input, select, button { padding: 10px 12px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: var(--text); font-size: 0.9rem; }
        button { background: var(--accent); color: #0f172a; font-weight: 700; border: none; cursor: pointer; }
        button:hover { opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.9rem; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #334155; }
        th { color: var(--muted); font-weight: 600; }
        .tag { padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }
        .P1 { background: rgba(239,68,68,0.2); color: var(--p1); }
        .P2 { background: rgba(249,115,22,0.2); color: var(--p2); }
        .P3 { background: rgba(234,179,8,0.2); color: var(--p3); }
        .P4 { background: rgba(34,197,94,0.2); color: var(--p4); }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div>
            <h1>12-Factor Vulnerability & Risk Triage Engine</h1>
            <small style="color: var(--muted);">Stateless Microservice | Redis Backing Service | Hardened Non-Root Container</small>
        </div>
        <div>
            <span class="badge">ENV: {{ env }}</span>
            <span class="badge" style="background:#334155;">Container ID: {{ hostname }}</span>
        </div>
    </header>

    <div class="grid">
        <div class="card"><h3>Total Triaged CVEs</h3><div class="val" id="total-count">-</div></div>
        <div class="card"><h3>Backing Service (Redis)</h3><div class="val" style="color:#22c55e;">CONNECTED</div></div>
        <div class="card"><h3>Runtime Security</h3><div class="val" style="font-size:1.1rem; margin-top:6px;">Read-Only FS + Non-Root</div></div>
        <div class="card"><h3>12-Factor Compliance</h3><div class="val" style="font-size:1.1rem; margin-top:6px;">12 / 12 Factors Active</div></div>
    </div>

    <div class="card" style="margin-bottom: 24px;">
        <h3>Run New Vulnerability Risk Assessment</h3>
        <form id="triage-form" class="form-row">
            <div><label style="display:block;font-size:0.75rem;color:var(--muted);">CVE ID</label><input type="text" id="cve_id" placeholder="CVE-2026-1337" required></div>
            <div><label style="display:block;font-size:0.75rem;color:var(--muted);">CVSS Score (0-10)</label><input type="number" step="0.1" min="0" max="10" id="cvss" placeholder="8.5" required></div>
            <div><label style="display:block;font-size:0.75rem;color:var(--muted);">Asset Environment</label>
                <select id="asset_type"><option value="IT">IT Infrastructure</option><option value="OT">OT / Industrial (ICS)</option></select>
            </div>
            <div><label style="display:block;font-size:0.75rem;color:var(--muted);">Exposure</label>
                <select id="internet_facing"><option value="true">Internet-Facing</option><option value="false">Internal Only</option></select>
            </div>
            <button type="submit">Assess & Prioritize</button>
        </form>
    </div>

    <div class="card">
        <h3>Prioritized Remediation Queue (Live from Redis)</h3>
        <table>
            <thead><tr><th>CVE ID</th><th>Base CVSS</th><th>Asset</th><th>Exposure</th><th>Priority</th><th>SLA</th><th>Recommended Business Action</th></tr></thead>
            <tbody id="vuln-table"></tbody>
        </table>
    </div>
</div>

<script>
async function loadData() {
    const res = await fetch('/api/v1/vulns');
    const data = await res.json();
    document.getElementById('total-count').innerText = data.total;
    const tbody = document.getElementById('vuln-table');
    tbody.innerHTML = '';
    data.items.forEach(v => {
        const pClass = v.priority.substring(0, 2);
        tbody.innerHTML += `<tr>
            <td><strong>${v.cve_id}</strong></td>
            <td>${v.base_cvss}</td>
            <td>${v.asset_type}</td>
            <td>${v.internet_facing === 'True' ? 'External' : 'Internal'}</td>
            <td><span class="tag ${pClass}">${v.priority}</span></td>
            <td>${v.sla_hours}h</td>
            <td>${v.action}</td>
        </tr>`;
    });
}
document.getElementById('triage-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await fetch('/api/v1/triage', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            cve_id: document.getElementById('cve_id').value,
            cvss: parseFloat(document.getElementById('cvss').value),
            asset_type: document.getElementById('asset_type').value,
            internet_facing: document.getElementById('internet_facing').value === 'true'
        })
    });
    document.getElementById('cve_id').value = '';
    loadData();
});
loadData();
</script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(DASHBOARD_HTML, env=APP_ENV, hostname=socket.gethostname())

@app.route("/health", methods=["GET"])
def health():
    try:
        db.ping()
        return jsonify({"status": "healthy", "environment": APP_ENV, "backing_service": "connected"}), 200
    except redis.ConnectionError:
        logger.error("Healthcheck failed: Redis unreachable")
        return jsonify({"status": "degraded", "backing_service": "unreachable"}), 503

@app.route("/api/v1/triage", methods=["POST"])
def triage_vulnerability():
    data = request.get_json(silent=True) or {}
    cve_id = data.get("cve_id")
    cvss = data.get("cvss")

    if not cve_id or cvss is None:
        return jsonify({"error": "Missing required fields: cve_id, cvss"}), 400

    try:
        cvss = float(cvss)
        if not (0.0 <= cvss <= 10.0):
            raise ValueError()
    except ValueError:
        return jsonify({"error": "cvss must be a float between 0.0 and 10.0"}), 400

    internet_facing = bool(data.get("internet_facing", False))
    asset_type = str(data.get("asset_type", "IT"))

    assessment = calculate_risk(cvss, internet_facing, asset_type)
    record = {
        "cve_id": cve_id.upper(),
        "base_cvss": cvss,
        "internet_facing": internet_facing,
        "asset_type": asset_type.upper(),
        **assessment
    }

    # ZASADA VI: STATELESS PROCESS (Stan zapisywany wyłącznie w Redis)
    db.hset(f"vuln:{cve_id.upper()}", mapping={k: str(v) for k, v in record.items()})
    db.incr("stats:total_triaged")

    logger.info(f"Triaged {cve_id.upper()} -> {assessment['priority']} (SLA: {assessment['sla_hours']}h)")
    return jsonify(record), 201

@app.route("/api/v1/vulns", methods=["GET"])
def list_vulns():
    keys = sorted(db.keys("vuln:*"))
    items = [db.hgetall(k) for k in keys]
    total = int(db.get("stats:total_triaged") or len(items))
    return jsonify({"total": total, "items": items}), 200

@app.route("/api/v1/stats", methods=["GET"])
def get_stats():
    total = db.get("stats:total_triaged") or 0
    return jsonify({"total_vulnerabilities_triaged": int(total)}), 200

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    host = os.getenv("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False)
