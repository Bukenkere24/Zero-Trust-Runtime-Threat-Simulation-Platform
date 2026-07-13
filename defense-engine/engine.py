"""Blue-team defense engine — log monitor, rule engine, and APIs."""

import json
import os
import re
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
ACCESS_LOG = DATA_DIR / "access.log"
ALERTS_LOG = DATA_DIR / "alerts.log"
BLOCKLIST_PATH = DATA_DIR / "blocklist.json"

BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW_SEC = int(os.environ.get("BRUTE_FORCE_WINDOW_SEC", "60"))
RATE_ABUSE_THRESHOLD = int(os.environ.get("RATE_ABUSE_THRESHOLD", "20"))
RATE_ABUSE_WINDOW_SEC = int(os.environ.get("RATE_ABUSE_WINDOW_SEC", "30"))

SQLI_PATTERNS = [
    r"'\s*OR\s*",
    r"--",
    r"UNION\s+SELECT",
    r"'\s*=\s*'",
    r"1\s*=\s*1",
]

_monitor_state = {
    "last_offset": 0,
    "alerts": [],
    "processed_alert_ids": set(),
}
_lock = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _load_blocklist() -> dict:
    if BLOCKLIST_PATH.exists():
        with open(BLOCKLIST_PATH, encoding="utf-8") as f:
            return json.load(f)
    return {"updated_at": _utc_now(), "blocked_ips": []}


def _save_blocklist(data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = _utc_now()
    with open(BLOCKLIST_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _append_alert(alert: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(ALERTS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")
    with _lock:
        _monitor_state["alerts"].append(alert)


def _block_ip(ip: str, reason: str, alert_id: str) -> None:
    blocklist = _load_blocklist()
    existing = {e["ip"] for e in blocklist.get("blocked_ips", [])}
    if ip not in existing:
        blocklist.setdefault("blocked_ips", []).append({
            "ip": ip,
            "blocked_at": _utc_now(),
            "reason": reason,
            "alert_id": alert_id,
        })
        _save_blocklist(blocklist)

    with _lock:
        for alert in _monitor_state["alerts"]:
            if alert["id"] == alert_id and not alert.get("remediated_at"):
                alert["remediated_at"] = _utc_now()


def _is_sqli(username: str) -> bool:
    text = username.upper()
    return any(re.search(p, text, re.IGNORECASE) for p in SQLI_PATTERNS)


def _analyze_entries(entries: list[dict]) -> None:
    now = datetime.now(timezone.utc)
    by_ip: dict[str, list[dict]] = defaultdict(list)

    for entry in entries:
        ip = entry.get("ip", "unknown")
        by_ip[ip].append(entry)

        username = entry.get("username", "")
        if entry.get("path") == "/login" and _is_sqli(username):
            alert_id = f"alert-{uuid.uuid4().hex[:8]}"
            alert = {
                "id": alert_id,
                "timestamp": _utc_now(),
                "severity": "high",
                "attack_type": "sql_injection",
                "source_ip": ip,
                "details": f"SQLi pattern in login: {username[:80]}",
            }
            _append_alert(alert)
            _block_ip(ip, "sql_injection_detected", alert_id)

    for ip, ip_entries in by_ip.items():
        recent_logins = []
        recent_requests = []
        for e in ip_entries:
            try:
                ts = _parse_ts(e["timestamp"])
            except (KeyError, ValueError):
                continue
            age = (now - ts).total_seconds()
            if e.get("path") == "/login" and e.get("status") in (401, 200) and age <= BRUTE_FORCE_WINDOW_SEC:
                recent_logins.append(e)
            if age <= RATE_ABUSE_WINDOW_SEC:
                recent_requests.append(e)

        if len(recent_logins) >= BRUTE_FORCE_THRESHOLD:
            alert_id = f"alert-{uuid.uuid4().hex[:8]}"
            alert = {
                "id": alert_id,
                "timestamp": _utc_now(),
                "severity": "high",
                "attack_type": "brute_force",
                "source_ip": ip,
                "details": f"{len(recent_logins)} login attempts in {BRUTE_FORCE_WINDOW_SEC}s",
            }
            _append_alert(alert)
            _block_ip(ip, "brute_force_detected", alert_id)

        if len(recent_requests) >= RATE_ABUSE_THRESHOLD:
            alert_id = f"alert-{uuid.uuid4().hex[:8]}"
            alert = {
                "id": alert_id,
                "timestamp": _utc_now(),
                "severity": "medium",
                "attack_type": "rate_abuse",
                "source_ip": ip,
                "details": f"{len(recent_requests)} requests in {RATE_ABUSE_WINDOW_SEC}s",
            }
            _append_alert(alert)
            _block_ip(ip, "rate_abuse_detected", alert_id)


def _tail_access_log() -> None:
    if not ACCESS_LOG.exists():
        return
    with open(ACCESS_LOG, encoding="utf-8") as f:
        f.seek(_monitor_state["last_offset"])
        new_lines = f.readlines()
        _monitor_state["last_offset"] = f.tell()

    entries = []
    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if entries:
        _analyze_entries(entries)


def _load_historical_alerts() -> None:
    if not ALERTS_LOG.exists():
        return
    with open(ALERTS_LOG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                if alert["id"] not in _monitor_state["processed_alert_ids"]:
                    _monitor_state["alerts"].append(alert)
                    _monitor_state["processed_alert_ids"].add(alert["id"])
            except (json.JSONDecodeError, KeyError):
                continue


def _monitor_loop() -> None:
    _load_historical_alerts()
    while True:
        try:
            _tail_access_log()
        except Exception:
            pass
        time.sleep(2)


def _compute_mttd() -> float:
    """Mean seconds from first access entry to alert for each IP."""
    if not ACCESS_LOG.exists() or not _monitor_state["alerts"]:
        return 0.0

    deltas = []
    access_by_ip: dict[str, list[datetime]] = defaultdict(list)
    with open(ACCESS_LOG, encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
                access_by_ip[entry["ip"]].append(_parse_ts(entry["timestamp"]))
            except (json.JSONDecodeError, KeyError, ValueError):
                continue

    for alert in _monitor_state["alerts"]:
        ip = alert.get("source_ip")
        if not ip or ip not in access_by_ip:
            continue
        first_access = min(access_by_ip[ip])
        alert_time = _parse_ts(alert["timestamp"])
        deltas.append((alert_time - first_access).total_seconds())

    return round(sum(deltas) / len(deltas), 2) if deltas else 0.0


def _compute_mttr() -> float:
    """Mean seconds from alert to remediation."""
    deltas = []
    for alert in _monitor_state["alerts"]:
        if alert.get("remediated_at"):
            try:
                t0 = _parse_ts(alert["timestamp"])
                t1 = _parse_ts(alert["remediated_at"])
                deltas.append((t1 - t0).total_seconds())
            except ValueError:
                continue
    return round(sum(deltas) / len(deltas), 2) if deltas else 0.0


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/alerts")
def alerts():
    with _lock:
        sorted_alerts = sorted(
            _monitor_state["alerts"],
            key=lambda a: a.get("timestamp", ""),
            reverse=True,
        )
    return jsonify({"alerts": sorted_alerts})


@app.route("/blocklist")
def blocklist():
    return jsonify(_load_blocklist())


@app.route("/metrics")
def metrics():
    with _lock:
        alerts = list(_monitor_state["alerts"])
    severity_counts: dict[str, int] = defaultdict(int)
    for a in alerts:
        severity_counts[a.get("severity", "unknown")] += 1

    blocklist_data = _load_blocklist()
    blocked_attempts = 0
    if ACCESS_LOG.exists():
        with open(ACCESS_LOG, encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry.get("blocked"):
                        blocked_attempts += 1
                except json.JSONDecodeError:
                    continue

    return jsonify({
        "total_alerts": len(alerts),
        "alerts_by_severity": dict(severity_counts),
        "blocked_ip_count": len(blocklist_data.get("blocked_ips", [])),
        "blocked_attempts": blocked_attempts,
        "mttd_seconds": _compute_mttd(),
        "mttr_seconds": _compute_mttr(),
    })


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not BLOCKLIST_PATH.exists():
        _save_blocklist({"blocked_ips": []})

    monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    monitor_thread.start()

    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
