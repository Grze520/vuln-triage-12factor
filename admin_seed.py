import os
import sys
import json
from datetime import datetime, timezone
import redis
from app import calculate_risk

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

SAMPLE_VULNS = [
    {"cve_id": "CVE-2024-3094", "cvss": 10.0, "internet_facing": True, "asset_type": "IT"},
    {"cve_id": "CVE-2023-4966", "cvss": 9.4, "internet_facing": True, "asset_type": "IT"},
    {"cve_id": "CVE-2024-21762", "cvss": 9.6, "internet_facing": True, "asset_type": "OT"},
    {"cve_id": "CVE-2023-23397", "cvss": 6.5, "internet_facing": False, "asset_type": "IT"},
]

def seed():
    db = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_connect_timeout=3)
    try:
        db.ping()
    except redis.ConnectionError as e:
        print(json.dumps({"level": "ERROR", "message": f"Cannot connect to Redis at {REDIS_HOST}:{REDIS_PORT} - {e}"}))
        sys.exit(1)

    for item in SAMPLE_VULNS:
        assessment = calculate_risk(item["cvss"], item["internet_facing"], item["asset_type"])
        record = {
            "cve_id": item["cve_id"],
            "base_cvss": item["cvss"],
            "internet_facing": item["internet_facing"],
            "asset_type": item["asset_type"],
            **assessment
        }
        db.hset(f"vuln:{item['cve_id']}", mapping={k: str(v) for k, v in record.items()})
        db.incr("stats:total_triaged")

    print(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "INFO",
        "task": "admin_seed",
        "message": f"Successfully seeded {len(SAMPLE_VULNS)} sample vulnerabilities."
    }))
    db.close()

if __name__ == "__main__":
    seed()
