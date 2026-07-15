# Changelog

## Chapter 1: Project Scaffold & Shared Contracts

- **What was built**: Set up the project directory structure with placeholder folders (`target-app`, `defense-engine`, `attacker-agent`, `dashboard`), established the `docker-compose.yml` skeleton, and created `CONTRACTS.md` defining the shared data/logging schemas.
- **Files Changed / Created**:
  - `target-app/.gitkeep` (NEW)
  - `defense-engine/.gitkeep` (NEW)
  - `attacker-agent/.gitkeep` (NEW)
  - `dashboard/.gitkeep` (NEW)
  - `docker-compose.yml` (NEW)
  - `CONTRACTS.md` (NEW)
- **Shared Contracts Defined**:
  - **Port Assignments**: `target-app` (5000), `defense-engine` (5001), `attacker-agent` (5002), `dashboard` (3000/5173).
  - **access.log**: JSON Lines format containing `timestamp`, `ip`, `action` (`login_attempt`|`api_call`|`blocked_attempt`), `result` (`success`|`failure`|`blocked`), and `context`.
  - **blocklist.json**: JSON Array of objects containing `ip`, `reason`, `blocked_at`.
  - **alerts.log**: JSON Lines format containing `timestamp`, `ip`, `rule_triggered`, `severity` (`low`|`medium`|`high`).
- **Next Chapter Dependency**:
  - Chapter 2 depends on the `access.log` schema and the `target-app` port assignment (5000) defined in `CONTRACTS.md` to build the actual Flask application core with a SQLite database.

## Chapter 2: Target App Core Build

- **What was built**: A deliberately vulnerable Flask web application matching the `CONTRACTS.md` schemas, featuring SQLite database initialization, idempotent user seeding, vulnerable raw SQL authentication, dynamic styled login/dashboard pages, and automated logging of logins/API calls to `logs/access.log`.
- **Files Changed / Created**:
  - `target-app/requirements.txt` (NEW)
  - `target-app/app.py` (NEW)
  - `target-app/templates/login.html` (NEW)
  - `target-app/templates/dashboard.html` (NEW)
- **Shared Contracts Maintained**:
  - `target-app` runs on port `5000`.
  - Appends logs to `logs/access.log` matching the JSON Lines schema specified in Chapter 1.
- **Next Chapter Dependency**:
  - Chapter 3 depends on the `target-app` files, database schema, and log files to containerize the target application using Docker, and set up volumes/healthchecks.

## Chapter 3: Containerize & Verify

- **What was built**: Containerized the `target-app` using a lightweight Dockerfile and configured `docker-compose.yml` to define port forwarding, a healthcheck mapping, and a persistent logging volume mount. Created developer documentation in `target-app/README.md`.
- **Files Changed / Created**:
  - `target-app/Dockerfile` (NEW)
  - `target-app/README.md` (NEW)
  - `docker-compose.yml` (MODIFY)
- **Shared Contracts Maintained**:
  - Port `5000` is mapped and exposed.
  - Logging directory is shared via Docker volume mapping.
- **Next Chapter Dependency**:
  - Chapter 4 depends on the container configurations and the `target-app` log files directory to implement the `defense-engine` log tailing and dynamic IP blocking.

## Chapter 4: Defense Engine (Detection & Enforcement)

- **What was built**: Built the `defense-engine` Python Flask application on port `5001` with background thread real-time log tailing of `access.log`. Implemented pluggable rules for:
  - Brute Force (>5 failed attempts in 30s)
  - SQL Injection (detecting SQL keywords in username fields)
  - Rate Limit Abuse (>20 API calls in 10s)
  Integrated enforcement into `target-app` via a blocklist checking middleware that returns HTTP `403 Forbidden` and logs a `blocked_attempt` to `access.log`.
- **Files Changed / Created**:
  - `defense-engine/requirements.txt` (NEW)
  - `defense-engine/app.py` (NEW)
  - `defense-engine/Dockerfile` (NEW)
  - `target-app/app.py` (MODIFY)
  - `docker-compose.yml` (MODIFY)
  - `blocklist.json` (NEW)
- **Shared Contracts Maintained**:
  - Exposes port `5001` for defense API.
  - Mounts shared named volumes for tailing `access.log` and sharing `blocklist.json`.
- **Next Chapter Dependency**:
  - Chapter 5 depends on the logs, alerts database, and shared blocklist of the target and defense engines to compute security metrics.




## 2026-07-15 — Full four-service verification (target-app + defense-engine + attacker-agent)

Ran the complete system locally (outside Docker) for the first time and verified the
full attack -> detect -> block loop end-to-end using the real attacker-agent.

### Confirmed working
- attacker-agent's heuristic decision engine (USE_LLM=0 path): correctly leads with
  sql_injection_login, then adapts round-to-round based on prior outcomes
  ("Avoiding [...], which the defense already blocked").
- Round 1 SQL injection against /login succeeded (200, bypassed auth), was picked up
  by defense-engine's log tailer ~1.6s later, written to alerts.log, and the source IP
  was auto-blocked within 2ms of the alert.
- /metrics, /alerts, /blocklist, and /attack_log all agree with each other once run
  against a genuinely clean data directory.

### Bugs found and fixed locally (not yet in committed code)
1. Missing dependency: defense-engine/requirements.txt does not list flask-cors, but
   engine.py imports it directly - `pip install flask-cors` needed manually.
2. Default target for local (non-Docker) runs: attacker-agent defaults to
   http://target-app:5000 (the Docker service name), which fails to resolve outside
   docker-compose. Must pass target_url explicitly in /start AND set TARGET_URL env
   var - agent.py's safety.py allowlist already permits localhost/127.0.0.1, so this
   is purely a default-value issue, not a safety restriction.
3. All three services read DATA_DIR from an environment variable defaulting to
   /app/data (the Docker mount path). Running locally requires explicitly setting
   $env:DATA_DIR to a real local folder in every terminal, every session - it does
   not persist across terminal restarts.
4. Running two copies of api.py simultaneously on the same port caused inconsistent
   state (blocklist edits silently reverted, alerts.log never written) - always
   confirm `Get-Process python` shows exactly one process per service before testing.

### Still to investigate
- attacker-agent's run stopped after round 1 of a requested 10 despite no error in
  its console output. Need to check AttackAgent.run()'s loop condition to confirm
  whether early-exit-on-first-success is intentional design or a bug.
