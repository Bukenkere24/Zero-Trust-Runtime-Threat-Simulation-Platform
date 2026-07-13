"""Flask trigger API — port 5002."""

import json
import os
import threading
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

from agent import AttackAgent, ATTACK_LOG_PATH

load_dotenv()

app = Flask(__name__)
CORS(app)

_run_lock = threading.Lock()
_run_state = {
    "active": False,
    "run_id": None,
    "current_round": 0,
    "total_rounds": 10,
    "thread": None,
}


def _read_attack_log() -> dict:
    path = Path(os.environ.get("ATTACK_LOG_PATH", str(ATTACK_LOG_PATH)))
    if not path.exists():
        return {"status": "idle", "rounds": []}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _run_agent(rounds: int, target_url: str | None) -> None:
    def on_progress(current, total, _entry):
        with _run_lock:
            _run_state["current_round"] = current
            _run_state["total_rounds"] = total

    try:
        agent = AttackAgent(target_url=target_url, rounds=rounds)
        with _run_lock:
            _run_state["run_id"] = None
        log = agent.run(progress_callback=on_progress)
        with _run_lock:
            _run_state["run_id"] = log.get("run_id")
    finally:
        with _run_lock:
            _run_state["active"] = False
            _run_state["current_round"] = 0


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/start", methods=["POST"])
def start():
    with _run_lock:
        if _run_state["active"]:
            return jsonify({"error": "A run is already active"}), 409

        body = request.get_json(silent=True) or {}
        rounds = int(body.get("rounds", 10))
        target_url = body.get("target_url")

        _run_state["active"] = True
        _run_state["current_round"] = 0
        _run_state["total_rounds"] = rounds
        _run_state["run_id"] = "starting"

        thread = threading.Thread(
            target=_run_agent,
            args=(rounds, target_url),
            daemon=True,
        )
        _run_state["thread"] = thread
        thread.start()

    return jsonify({"status": "started", "rounds": rounds})


@app.route("/status", methods=["GET"])
def status():
    with _run_lock:
        return jsonify({
            "active": _run_state["active"],
            "run_id": _run_state["run_id"],
            "current_round": _run_state["current_round"],
            "total_rounds": _run_state["total_rounds"],
        })


@app.route("/attack_log", methods=["GET"])
def attack_log():
    return jsonify(_read_attack_log())


def _build_summary(rounds, metrics, alerts) -> str:
    """Deterministic, LLM-free scorecard narrative built from the raw numbers."""
    total = len(rounds)
    succeeded = sum(1 for r in rounds if r.get("success") and not r.get("blocked"))
    blocked = sum(1 for r in rounds if r.get("blocked"))
    failed = total - succeeded - blocked

    by_type: dict[str, dict[str, int]] = {}
    for r in rounds:
        t = r.get("attack_type", "unknown")
        bucket = by_type.setdefault(t, {"succeeded": 0, "blocked": 0, "failed": 0})
        if r.get("success") and not r.get("blocked"):
            bucket["succeeded"] += 1
        elif r.get("blocked"):
            bucket["blocked"] += 1
        else:
            bucket["failed"] += 1

    mttd = metrics.get("mttd_seconds", 0)
    mttr = metrics.get("mttr_seconds", 0)
    blocked_ips = metrics.get("blocked_ip_count", 0)

    if total == 0:
        return "No attacks were executed in this run."

    detection_rate = round((blocked / total) * 100) if total else 0

    if succeeded == 0 and blocked > 0:
        verdict = (
            "The defense engine performed strongly: every breach attempt was detected and "
            "the offending source was blocked before authentication could be bypassed."
        )
    elif succeeded > 0 and blocked > 0:
        verdict = (
            "The defense engine caught and blocked several attacks, but the target still exposed "
            "exploitable weaknesses that succeeded before enforcement kicked in."
        )
    elif succeeded > 0 and blocked == 0:
        verdict = (
            "The target was breached without triggering any blocks — the defense engine failed to "
            "detect or remediate the attacks in time."
        )
    else:
        verdict = "No attacks succeeded, though the defense did not need to block any source."

    per_type = "; ".join(
        f"{t}: {b['succeeded']} succeeded / {b['blocked']} blocked / {b['failed']} failed"
        for t, b in by_type.items()
    )

    return (
        f"The simulation ran {total} attack rounds — {succeeded} succeeded, {blocked} were blocked, "
        f"and {failed} failed. The defense detected and blocked {detection_rate}% of attempts across "
        f"{blocked_ips} unique source IP(s), with a Mean Time To Detect of {mttd}s and a Mean Time To "
        f"Remediate of {mttr}s. Breakdown by attack type — {per_type}. {verdict}"
    )


@app.route("/summarize", methods=["POST"])
def summarize():
    """Generate a scorecard summary.

    Uses a deterministic, free summary by default. Only calls the LLM when
    USE_LLM=1 and an ANTHROPIC_API_KEY is set; falls back to the free summary
    on any error.
    """
    body = request.get_json(silent=True) or {}
    attack_log = body.get("attackLog", {})
    metrics = body.get("metrics", {})
    alerts = body.get("alerts", [])
    rounds = attack_log.get("rounds", [])

    fallback = _build_summary(rounds, metrics, alerts)

    use_llm = os.environ.get("USE_LLM", "0") == "1"
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not (use_llm and api_key):
        return jsonify({"summary": fallback, "source": "heuristic"})

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        prompt = f"""Summarize this red-team vs blue-team security simulation in 3-4 sentences for a portfolio report.

Attack results: {json.dumps(rounds, indent=2)}
Defense metrics: {json.dumps(metrics, indent=2)}
Alerts: {json.dumps(alerts[:10], indent=2)}

Focus on how well the defense performed (detection, blocking, MTTD/MTTR). Be concise and professional."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        summary = message.content[0].text.strip()
        return jsonify({"summary": summary, "source": "llm"})
    except Exception:
        return jsonify({"summary": fallback, "source": "heuristic"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    app.run(host="0.0.0.0", port=port, debug=False)
