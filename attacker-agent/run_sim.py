"""Run a local attacker simulation and print results."""
import json
import time
import urllib.request

def get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())

def post(url, body=None):
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

TARGET = "http://localhost:5003"

for name, url in [
    ("target", f"{TARGET}/health"),
    ("defense", "http://localhost:5001/health"),
    ("attacker", "http://localhost:5002/health"),
]:
    print(f"{name}: {get(url)}")

print("\nStarting simulation (5 rounds)...")
print(post("http://localhost:5002/start", {"rounds": 5, "target_url": TARGET}))

rounds = []
for i in range(60):
    status = get("http://localhost:5002/status")
    log = get("http://localhost:5002/attack_log")
    rounds = log.get("rounds", [])
    print(
        f"  [{i + 1}] active={status['active']} "
        f"round={status['current_round']}/{status['total_rounds']} "
        f"attacks_logged={len(rounds)}"
    )
    if not status["active"] and log.get("status") == "completed":
        break
    time.sleep(2)

print("\n" + "=" * 60)
print("ATTACK LOG")
print("=" * 60)
for r in rounds:
    if r.get("success") and not r.get("blocked"):
        outcome = "BREACH"
    elif r.get("blocked"):
        outcome = "BLOCKED"
    else:
        outcome = "FAILED"
    print(f"Round {r['round']}: {r['attack_type']} -> {outcome}")
    print(f"  Payload: {r.get('payload_used', '')}")
    reason = r.get("llm_reasoning", "")
    print(f"  Reason:  {reason[:90]}")
    print()

print("=" * 60)
print("DEFENSE METRICS")
print("=" * 60)
metrics = get("http://localhost:5001/metrics")
print(json.dumps(metrics, indent=2))

alerts = get("http://localhost:5001/alerts")
print(f"Alerts raised: {len(alerts.get('alerts', []))}")

blocklist = get("http://localhost:5001/blocklist")
print(f"IPs blocked: {len(blocklist.get('blocked_ips', []))}")

print("\n" + "=" * 60)
print("SCORECARD SUMMARY")
print("=" * 60)
summary = post("http://localhost:5002/summarize", {
    "attackLog": log,
    "metrics": metrics,
    "alerts": alerts.get("alerts", []),
})
print(summary.get("summary", ""))
print(f"(source: {summary.get('source', '')})")
