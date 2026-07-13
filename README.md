# Zero-Trust Runtime Threat Simulation Platform

A self-contained, sandboxed red-team vs blue-team security simulation. An AI-powered attacker agent probes a deliberately vulnerable web app while a rule-based defense engine detects and blocks attacks in real time. A live dashboard visualizes the battle and produces a final scorecard with MTTD, MTTR, and an LLM-generated summary.

## Architecture

```
┌─────────────┐     attacks      ┌─────────────┐
│  attacker-  │ ───────────────► │  target-app │  (port 5000)
│    agent    │                  │  (victim)   │
│  (port 5002)│                  └──────┬──────┘
└──────┬──────┘                         │ access.log
       │ attack_log.json                 ▼
       │                          ┌─────────────┐
       │                          │  defense-   │  (port 5001)
       │                          │   engine    │
       │                          └──────┬──────┘
       │                                 │ alerts, blocklist
       ▼                                 ▼
┌─────────────┐ ◄── polls every 2s ──────────────┐
│  dashboard  │                                  │
│ (port 5173) │                                  │
└─────────────┘                                  │
```

### Services

| Service | Port | Role |
|---------|------|------|
| **target-app** | 5000 | Vulnerable Flask app with login + `/api/users` |
| **defense-engine** | 5001 | Tails logs, detects attacks, blocks IPs |
| **attacker-agent** | 5002 | AI red-team agent + trigger API |
| **dashboard** | 5173 | Live battle view + simulation report |

### Shared Data (Docker volume `shared-data`)

- `access.log` — JSONL request log from target-app
- `alerts.log` — JSONL defense alerts
- `blocklist.json` — Blocked IPs with timestamps
- `attack_log.json` — LLM decisions and attack results

See [CONTRACTS.md](./CONTRACTS.md) for exact schemas.

## Quick Start

### Prerequisites

- Docker & Docker Compose
- No API key required — the agent ships with a free, built-in strategy engine

### Run the full simulation

```bash
docker-compose up --build
```

That's it — no keys, no cost. The attacker agent decides its moves with a
local heuristic "brain" (see below). An LLM is entirely optional; if you ever
want to enable it, set `USE_LLM=1` and `ANTHROPIC_API_KEY` in a `.env` file.

Open **http://localhost:5173** and click **Start Simulation**.

### Local development (without Docker)

**Terminal 1 — Target app:**
```bash
cd target-app && pip install -r requirements.txt && python app.py
```

**Terminal 2 — Defense engine:**
```bash
cd defense-engine && pip install -r requirements.txt && python engine.py
```

**Terminal 3 — Attacker agent:**
```bash
cd attacker-agent && pip install -r requirements.txt
set TARGET_URL=http://localhost:5000
python api.py
```

**Terminal 4 — Dashboard:**
```bash
cd dashboard && npm install && npm run dev
```

## Attacker Agent

### Decision brain (`agent.py`)

The agent decides which attack to run next using a **free heuristic strategy
engine** — no API key, no cost. It:

1. Follows an escalation order (stealthy → noisy): `sql_injection_login` →
   `credential_stuffing` → `brute_force_login` → `api_flood`.
2. Never repeats an attack the defense already blocked.
3. Never repeats one that already failed outright.
4. Re-probes a blocked attack once everything is exhausted, to test whether the
   block is still being enforced.

Each decision is logged with human-readable reasoning to `attack_log.json`, so
the dataset looks the same whether the brain is heuristic or LLM.

**Optional LLM upgrade:** set `USE_LLM=1` and `ANTHROPIC_API_KEY` to have Claude
choose attacks instead. Any error (bad key, no network, rate limit) silently
falls back to the heuristic engine, so a run never fails because of the LLM.

### Attack library (`attacks.py`)

| Function | Description |
|----------|-------------|
| `brute_force_login` | Tries common passwords against admin |
| `sql_injection_login` | SQLi payloads on login form |
| `api_flood` | Rapid GET requests to `/api/users` |
| `credential_stuffing` | Common username/password pairs |

### Safety guardrails (`safety.py`)

Every outbound request is validated against a hardcoded allowlist:
- `localhost`, `127.0.0.1`, `target-app`
- Requests to any other host are **rejected**

### API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/start` | POST | Start attack loop (background thread) |
| `/status` | GET | Whether a run is active |
| `/attack_log` | GET | Current attack log |
| `/summarize` | POST | Scorecard summary (free heuristic; LLM optional) |

## Dashboard

- **Start Simulation** — triggers attacker-agent `/start`
- **Live feeds** — polls attack log and defense alerts every 2 seconds
- **Battle view** — two-column red vs blue with timestamps
- **Simulation Report** — appears when run completes (MTTD, MTTR, auto-generated summary)

## Research / Paper Data

All four log files are timestamped JSON/JSONL and can be used to compute:

- Attack success rate by type
- Mean Time To Detect (MTTD)
- Mean Time To Remediate (MTTR)
- False positive rate
- Attack strategy evolution (`attack_log.json`)

## Project Structure

```
├── CONTRACTS.md          # Shared API/log schemas
├── docker-compose.yml    # One-command startup
├── target-app/           # Vulnerable victim app
├── defense-engine/       # Blue-team log monitor
├── attacker-agent/       # Red-team AI agent (Avaneesh)
│   ├── attacks.py        # Attack function library
│   ├── agent.py          # Heuristic decision engine (LLM optional)
│   ├── safety.py         # Host allowlist guardrails
│   ├── api.py            # Flask trigger API
│   └── stub_target.py    # Local stub for Day 1 testing
└── dashboard/            # React live dashboard (Avaneesh)
```

## License

Built for educational and research purposes. Never deploy the target-app outside a sandbox.
