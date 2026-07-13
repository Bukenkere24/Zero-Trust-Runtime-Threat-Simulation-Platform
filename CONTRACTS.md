# Shared Contracts — Zero-Trust Runtime Threat Simulation Platform

Agreed interfaces between target-app, defense-engine, attacker-agent, and dashboard.

## Ports

| Service         | Port | Notes                          |
|-----------------|------|--------------------------------|
| target-app      | 5000 | Vulnerable Flask web app       |
| defense-engine  | 5001 | Blue-team log monitor + APIs   |
| attacker-agent  | 5002 | Red-team trigger + status API  |
| dashboard       | 5173 | React (Vite dev server)        |

## target-app Endpoints

- `GET /` — Login page (HTML form)
- `POST /login` — Form fields: `username`, `password`
- `GET /api/users` — Returns JSON list of users (intentionally exposed)

### Login form field names

- `username` (text)
- `password` (password)

### /api/users response shape

```json
{
  "users": [
    {"id": 1, "username": "admin", "email": "admin@local"}
  ]
}
```

## access.log format

One JSON object per line (JSONL), written by target-app:

```json
{
  "timestamp": "2026-07-13T10:00:00.000Z",
  "ip": "172.18.0.5",
  "method": "POST",
  "path": "/login",
  "status": 200,
  "username": "admin",
  "user_agent": "attacker-agent/1.0",
  "blocked": false
}
```

Blocked requests include `"blocked": true` and `"block_reason": "ip_blocklist"`.

## blocklist.json schema

```json
{
  "updated_at": "2026-07-13T10:05:00.000Z",
  "blocked_ips": [
    {
      "ip": "172.18.0.5",
      "blocked_at": "2026-07-13T10:05:00.000Z",
      "reason": "brute_force_detected",
      "alert_id": "alert-001"
    }
  ]
}
```

## alerts.log format

One JSON object per line (JSONL), written by defense-engine:

```json
{
  "id": "alert-001",
  "timestamp": "2026-07-13T10:04:30.000Z",
  "severity": "high",
  "attack_type": "brute_force",
  "source_ip": "172.18.0.5",
  "details": "15 failed login attempts in 60s",
  "remediated_at": "2026-07-13T10:05:00.000Z"
}
```

## defense-engine API

### GET /alerts

```json
{
  "alerts": [ /* array of alert objects, newest first */ ]
}
```

### GET /blocklist

Returns the current `blocklist.json` contents.

### GET /metrics

```json
{
  "total_alerts": 5,
  "alerts_by_severity": {"low": 1, "medium": 2, "high": 2},
  "blocked_ip_count": 2,
  "blocked_attempts": 8,
  "mttd_seconds": 12.5,
  "mttr_seconds": 8.3
}
```

- **MTTD**: Mean time from first suspicious access.log entry to alert timestamp.
- **MTTR**: Mean time from alert timestamp to `remediated_at` (IP blocked).

## attack_log.json schema

Written by attacker-agent:

```json
{
  "run_id": "run-20260713-100000",
  "started_at": "2026-07-13T10:00:00.000Z",
  "finished_at": "2026-07-13T10:02:00.000Z",
  "status": "completed",
  "rounds": [
    {
      "round": 1,
      "timestamp": "2026-07-13T10:00:05.000Z",
      "llm_choice": "brute_force_login",
      "llm_reasoning": "Start with common passwords against admin.",
      "attack_type": "brute_force_login",
      "payload_used": "admin:password123",
      "success": false,
      "response_time_ms": 45,
      "blocked": false
    }
  ]
}
```

## attacker-agent API

### POST /start

Starts attack loop in background thread.

Request body (optional):

```json
{"rounds": 10, "target_url": "http://target-app:5000"}
```

Response:

```json
{"status": "started", "run_id": "run-20260713-100000"}
```

### GET /status

```json
{
  "active": true,
  "run_id": "run-20260713-100000",
  "current_round": 3,
  "total_rounds": 10
}
```

### GET /attack_log

Returns current `attack_log.json` contents.
