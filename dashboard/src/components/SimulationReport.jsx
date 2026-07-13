function StatCard({ label, value, sub, accent }) {
  const colors = {
    red: 'border-red-500/40 text-red-400',
    blue: 'border-defense/40 text-defense',
    green: 'border-green-500/40 text-green-400',
    yellow: 'border-yellow-500/40 text-yellow-400',
    gray: 'border-gray-600 text-gray-300',
  }

  return (
    <div className={`rounded-xl border bg-gray-900/50 p-5 ${colors[accent] || colors.gray}`}>
      <p className="text-xs uppercase tracking-wider text-gray-500">{label}</p>
      <p className="mt-2 text-3xl font-bold">{value}</p>
      {sub && <p className="mt-1 text-xs text-gray-500">{sub}</p>}
    </div>
  )
}

export function SimulationReport({ attackLog, metrics, blocklist, summary, onClose }) {
  const rounds = attackLog?.rounds || []
  const succeeded = rounds.filter((r) => r.success && !r.blocked).length
  const blocked = rounds.filter((r) => r.blocked).length
  const failed = rounds.length - succeeded - blocked

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-2xl border border-gray-700 bg-gray-900 p-8 shadow-2xl">
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h2 className="text-2xl font-bold">Simulation Report</h2>
            <p className="text-sm text-gray-400">Run ID: {attackLog?.run_id || '—'}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg bg-gray-800 px-3 py-1 text-sm hover:bg-gray-700"
          >
            Close
          </button>
        </div>

        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total Attacks" value={rounds.length} accent="gray" />
          <StatCard label="Succeeded" value={succeeded} accent="red" />
          <StatCard label="Blocked" value={blocked} accent="yellow" />
          <StatCard label="Failed" value={failed} accent="gray" />
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <StatCard
            label="MTTD"
            value={`${metrics?.mttd_seconds ?? 0}s`}
            sub="Mean Time To Detect"
            accent="blue"
          />
          <StatCard
            label="MTTR"
            value={`${metrics?.mttr_seconds ?? 0}s`}
            sub="Mean Time To Remediate"
            accent="green"
          />
          <StatCard
            label="IPs Blocked"
            value={blocklist?.blocked_ips?.length ?? metrics?.blocked_ip_count ?? 0}
            sub={`${metrics?.blocked_attempts ?? 0} blocked attempts`}
            accent="blue"
          />
        </div>

        {metrics?.alerts_by_severity && (
          <div className="mt-6 rounded-xl border border-gray-700 bg-gray-800/50 p-4">
            <h3 className="mb-2 text-sm font-semibold text-gray-400">Alerts by Severity</h3>
            <div className="flex gap-4">
              {Object.entries(metrics.alerts_by_severity).map(([sev, count]) => (
                <span key={sev} className="text-sm">
                  <span className="capitalize text-gray-300">{sev}</span>:{' '}
                  <span className="font-bold">{count}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="mt-6 rounded-xl border border-gray-700 bg-gray-800/50 p-5">
          <h3 className="mb-2 text-sm font-semibold text-gray-400">AI Summary</h3>
          <p className="leading-relaxed text-gray-300">{summary}</p>
        </div>
      </div>
    </div>
  )
}

export default SimulationReport
