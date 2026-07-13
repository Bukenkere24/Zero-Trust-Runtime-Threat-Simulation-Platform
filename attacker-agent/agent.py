"""AI decision layer — a heuristic strategy engine picks the next attack.

By default the agent uses a self-contained, rule-based "brain" (no API key, no
cost) that adapts to what has and hasn't worked. Setting USE_LLM=1 with an
ANTHROPIC_API_KEY present upgrades the brain to an LLM, but that is optional.
"""

import json
import os
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attacks import ATTACK_FUNCTIONS
from safety import get_default_target_url, validate_target_url

ATTACK_LOG_PATH = Path(os.environ.get("ATTACK_LOG_PATH", "data/attack_log.json"))

# Red-team escalation order: cheapest/stealthiest path to breach first, noisiest last.
STRATEGY_PRIORITY = [
    "sql_injection_login",   # single crafted request can bypass auth outright
    "credential_stuffing",   # targeted known pairs, low volume
    "brute_force_login",     # noisier password spray
    "api_flood",             # loudest, probes rate limiting
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _run_id() -> str:
    return f"run-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"


class AttackAgent:
    """Maintains state and runs the LLM-driven attack loop."""

    def __init__(
        self,
        target_url: str | None = None,
        rounds: int = 10,
        attack_log_path: Path | None = None,
    ):
        self.target_url = target_url or get_default_target_url()
        validate_target_url(self.target_url)
        self.rounds = rounds
        self.attack_log_path = attack_log_path or ATTACK_LOG_PATH
        self.state: dict[str, Any] = {
            "attacks_tried": [],
            "successes": [],
            "failures": [],
            "blocked": [],
            "target_status": "unknown",
        }
        self.log: dict[str, Any] = {}

    def _choose_attack(self) -> tuple[str, str]:
        """Pick the next attack.

        Uses the free heuristic strategy engine by default. Only calls the LLM
        when explicitly opted in via USE_LLM=1 and a key is present.
        """
        use_llm = os.environ.get("USE_LLM", "0") == "1"
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if use_llm and api_key:
            return self._choose_attack_llm(api_key)
        return self._choose_attack_heuristic()

    def _choose_attack_heuristic(self) -> tuple[str, str]:
        """Rule-based strategy: adapt to prior outcomes, no API cost.

        Logic:
        1. Never repeat an attack the defense already blocked.
        2. Never repeat one that already failed outright.
        3. Otherwise follow the escalation priority (stealthy -> noisy).
        4. If everything has been tried and nothing worked, retry the
           least-recently blocked option to probe whether the block expired.
        """
        tried = {a["attack"] for a in self.state["attacks_tried"]}
        blocked = set(self.state["blocked"])
        failed = set(self.state["failures"])
        exhausted = blocked | failed

        for attack in STRATEGY_PRIORITY:
            if attack in exhausted:
                continue
            if attack in tried:
                continue
            reason = self._reason_for(attack, first_try=True)
            return attack, reason

        # Fall back: try anything not yet attempted this run.
        for attack in STRATEGY_PRIORITY:
            if attack not in tried:
                return attack, self._reason_for(attack, first_try=True)

        # Everything tried. Re-probe the highest-priority non-successful option
        # in case a defensive block has aged out.
        for attack in STRATEGY_PRIORITY:
            if attack not in self.state["successes"]:
                return attack, (
                    f"All attacks exhausted; re-probing {attack} to test whether "
                    f"the defense is still enforcing its block."
                )

        return STRATEGY_PRIORITY[0], "All attacks succeeded already; re-running top priority."

    def _reason_for(self, attack: str, first_try: bool) -> str:
        blocked = self.state["blocked"]
        failed = self.state["failures"]
        rationales = {
            "sql_injection_login": "Leading with SQL injection — a single crafted payload can bypass authentication without generating login volume.",
            "credential_stuffing": "Trying known credential pairs next — low-volume and often effective against default accounts.",
            "brute_force_login": "Escalating to a password spray — broader coverage, though noisier and more detectable.",
            "api_flood": "Falling back to API flooding — the loudest option, useful for probing rate-limit defenses.",
        }
        base = rationales.get(attack, f"Selecting {attack}.")
        if blocked:
            base += f" Avoiding {sorted(set(blocked))}, which the defense already blocked."
        elif failed:
            base += f" Prior attempts {sorted(set(failed))} failed, so moving on."
        return base

    def _choose_attack_llm(self, api_key: str) -> tuple[str, str]:
        """Optional LLM brain (opt-in). Falls back to heuristic on any error."""
        available = list(ATTACK_FUNCTIONS.keys())
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=api_key)
            prompt = f"""You are a red-team security agent testing a deliberately vulnerable local web app.

Current state:
- Attacks tried: {json.dumps(self.state['attacks_tried'], indent=2)}
- Successful attacks: {json.dumps(self.state['successes'], indent=2)}
- Failed attacks: {json.dumps(self.state['failures'], indent=2)}
- Blocked by defense: {json.dumps(self.state['blocked'], indent=2)}
- Target status: {self.state['target_status']}

Available attack functions (choose EXACTLY one name):
{json.dumps(available)}

Respond with JSON only:
{{"attack": "<function_name>", "reasoning": "<brief explanation>"}}

Choose strategically based on what has and hasn't worked. Only pick from the listed function names."""

            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            text = message.content[0].text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()

            parsed = json.loads(text)
            choice = parsed.get("attack", "")
            reasoning = parsed.get("reasoning", "")

            if choice not in ATTACK_FUNCTIONS:
                return self._choose_attack_heuristic()

            return choice, f"[LLM] {reasoning}"
        except Exception:
            return self._choose_attack_heuristic()

    def _execute_attack(self, attack_name: str) -> dict[str, Any]:
        func = ATTACK_FUNCTIONS[attack_name]
        if attack_name == "brute_force_login":
            return func(self.target_url, username="admin")
        if attack_name == "api_flood":
            return func(self.target_url, endpoint="/api/users")
        return func(self.target_url)

    def _update_state(self, attack_name: str, result: dict[str, Any]) -> None:
        self.state["attacks_tried"].append({
            "attack": attack_name,
            "success": result.get("success", False),
            "blocked": result.get("blocked", False),
        })
        if result.get("blocked"):
            self.state["blocked"].append(attack_name)
            self.state["target_status"] = "blocking_active"
        elif result.get("success"):
            self.state["successes"].append(attack_name)
            self.state["target_status"] = "breached"
        else:
            self.state["failures"].append(attack_name)

    def _save_log(self) -> None:
        self.attack_log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.attack_log_path, "w", encoding="utf-8") as f:
            json.dump(self.log, f, indent=2)

    def run(self, progress_callback=None) -> dict[str, Any]:
        """Run the attack loop for configured rounds or until breach."""
        run_id = _run_id()
        self.log = {
            "run_id": run_id,
            "started_at": _utc_now(),
            "finished_at": None,
            "status": "running",
            "target_url": self.target_url,
            "rounds": [],
        }
        self._save_log()

        for round_num in range(1, self.rounds + 1):
            attack_name, reasoning = self._choose_attack()
            result = self._execute_attack(attack_name)
            self._update_state(attack_name, result)

            round_entry = {
                "round": round_num,
                "timestamp": result["timestamp"],
                "llm_choice": attack_name,
                "llm_reasoning": reasoning,
                **result,
            }
            self.log["rounds"].append(round_entry)
            self._save_log()

            if progress_callback:
                progress_callback(round_num, self.rounds, round_entry)

            if result.get("success") and not result.get("blocked"):
                break

        self.log["finished_at"] = _utc_now()
        self.log["status"] = "completed"
        self._save_log()
        return self.log
