const ATTACKER_URL = import.meta.env.VITE_ATTACKER_URL || 'http://localhost:5002'
const DEFENSE_URL = import.meta.env.VITE_DEFENSE_URL || 'http://localhost:5001'

export async function startSimulation(rounds = 10) {
  const res = await fetch(`${ATTACKER_URL}/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rounds }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error || `Start failed: ${res.status}`)
  }
  return res.json()
}

export async function fetchAttackStatus() {
  const res = await fetch(`${ATTACKER_URL}/status`)
  return res.json()
}

export async function fetchAttackLog() {
  const res = await fetch(`${ATTACKER_URL}/attack_log`)
  return res.json()
}

export async function fetchAlerts() {
  const res = await fetch(`${DEFENSE_URL}/alerts`)
  return res.json()
}

export async function fetchBlocklist() {
  const res = await fetch(`${DEFENSE_URL}/blocklist`)
  return res.json()
}

export async function fetchMetrics() {
  const res = await fetch(`${DEFENSE_URL}/metrics`)
  return res.json()
}

export async function generateSummary(attackLog, metrics, alerts) {
  const res = await fetch(`${ATTACKER_URL}/summarize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attackLog, metrics, alerts }),
  })
  if (!res.ok) {
    return buildFallbackSummary(attackLog, metrics)
  }
  const data = await res.json()
  return data.summary
}

function buildFallbackSummary(attackLog, metrics) {
  const rounds = attackLog.rounds || []
  const succeeded = rounds.filter((r) => r.success && !r.blocked).length
  const blocked = rounds.filter((r) => r.blocked).length
  const failed = rounds.length - succeeded - blocked

  return (
    `The simulation completed ${rounds.length} attack rounds. ` +
    `${succeeded} attacks succeeded, ${blocked} were blocked by the defense engine, ` +
    `and ${failed} failed without triggering a block. ` +
    `Mean Time To Detect was ${metrics.mttd_seconds ?? 'N/A'}s and ` +
    `Mean Time To Remediate was ${metrics.mttr_seconds ?? 'N/A'}s. ` +
  (blocked > succeeded
    ? 'The defense performed well, stopping most attack attempts.'
    : 'The target showed vulnerabilities that the defense did not fully mitigate.')
  )
}
