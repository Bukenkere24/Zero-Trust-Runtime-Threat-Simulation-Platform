function formatTime(ts) {
  if (!ts) return '—'
  try {
    return new Date(ts).toLocaleTimeString()
  } catch {
    return ts
  }
}

function AttackCard({ round }) {
  const blocked = round.blocked
  const success = round.success && !blocked

  return (
    <div
      className={`rounded-lg border p-3 text-sm ${
        success
          ? 'border-red-500/50 bg-red-950/40'
          : blocked
            ? 'border-yellow-500/50 bg-yellow-950/30'
            : 'border-gray-700 bg-gray-900/60'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-xs text-gray-400">{formatTime(round.timestamp)}</span>
        <span
          className={`rounded px-2 py-0.5 text-xs font-semibold ${
            success ? 'bg-red-600' : blocked ? 'bg-yellow-600' : 'bg-gray-700'
          }`}
        >
          {success ? 'BREACH' : blocked ? 'BLOCKED' : 'FAILED'}
        </span>
      </div>
      <p className="mt-1 font-semibold text-attack">{round.attack_type}</p>
      <p className="text-xs text-gray-400">Payload: {round.payload_used}</p>
      <p className="mt-1 text-xs italic text-gray-500">{round.llm_reasoning}</p>
      <p className="mt-1 text-xs text-gray-500">{round.response_time_ms}ms</p>
    </div>
  )
}

function DefenseCard({ alert }) {
  const severityColor = {
    high: 'bg-red-600',
    medium: 'bg-yellow-600',
    low: 'bg-blue-600',
  }

  return (
    <div className="rounded-lg border border-defense/30 bg-defense-light/10 p-3 text-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-xs text-gray-400">{formatTime(alert.timestamp)}</span>
        <span className={`rounded px-2 py-0.5 text-xs font-semibold ${severityColor[alert.severity] || 'bg-gray-700'}`}>
          {alert.severity?.toUpperCase()}
        </span>
      </div>
      <p className="mt-1 font-semibold text-defense">{alert.attack_type}</p>
      <p className="text-xs text-gray-400">IP: {alert.source_ip}</p>
      <p className="mt-1 text-xs text-gray-500">{alert.details}</p>
      {alert.remediated_at && (
        <p className="mt-1 text-xs text-green-400">Remediated: {formatTime(alert.remediated_at)}</p>
      )}
    </div>
  )
}

export function BattleView({ attacks, defenses }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div>
        <h3 className="mb-3 flex items-center gap-2 text-lg font-bold text-attack">
          <span className="inline-block h-3 w-3 rounded-full bg-attack" />
          Red Team — Attacks
        </h3>
        <div className="max-h-[28rem] space-y-2 overflow-y-auto pr-1">
          {attacks.length === 0 ? (
            <p className="text-sm text-gray-500">Waiting for attacks...</p>
          ) : (
            [...attacks].reverse().map((round, i) => (
              <AttackCard key={`${round.round}-${i}`} round={round} />
            ))
          )}
        </div>
      </div>

      <div>
        <h3 className="mb-3 flex items-center gap-2 text-lg font-bold text-defense">
          <span className="inline-block h-3 w-3 rounded-full bg-defense" />
          Blue Team — Defense
        </h3>
        <div className="max-h-[28rem] space-y-2 overflow-y-auto pr-1">
          {defenses.length === 0 ? (
            <p className="text-sm text-gray-500">Waiting for alerts...</p>
          ) : (
            defenses.map((alert) => <DefenseCard key={alert.id} alert={alert} />)
          )}
        </div>
      </div>
    </div>
  )
}

export default BattleView
