import { useCallback, useEffect, useRef, useState } from 'react'
import BattleView from './components/BattleView'
import SimulationReport from './components/SimulationReport'
import {
  fetchAlerts,
  fetchAttackLog,
  fetchAttackStatus,
  fetchBlocklist,
  fetchMetrics,
  generateSummary,
  startSimulation,
} from './api'

const POLL_MS = 2000

export default function App() {
  const [running, setRunning] = useState(false)
  const [attacks, setAttacks] = useState([])
  const [defenses, setDefenses] = useState([])
  const [blocklist, setBlocklist] = useState({ blocked_ips: [] })
  const [status, setStatus] = useState({ active: false, current_round: 0, total_rounds: 10 })
  const [showReport, setShowReport] = useState(false)
  const [reportData, setReportData] = useState(null)
  const [error, setError] = useState(null)
  const wasActive = useRef(false)

  const poll = useCallback(async () => {
    try {
      const [attackLog, alertsData, blocklistData, statusData] = await Promise.all([
        fetchAttackLog(),
        fetchAlerts(),
        fetchBlocklist(),
        fetchAttackStatus(),
      ])

      setAttacks(attackLog.rounds || [])
      setDefenses(alertsData.alerts || [])
      setBlocklist(blocklistData)
      setStatus(statusData)
      setRunning(statusData.active)

      if (wasActive.current && !statusData.active && (attackLog.rounds?.length ?? 0) > 0) {
        const metrics = await fetchMetrics()
        const summary = await generateSummary(attackLog, metrics, alertsData.alerts)
        setReportData({ attackLog, metrics, blocklist: blocklistData, summary })
        setShowReport(true)
      }
      wasActive.current = statusData.active
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => {
    poll()
    const id = setInterval(poll, POLL_MS)
    return () => clearInterval(id)
  }, [poll])

  const handleStart = async () => {
    setError(null)
    setShowReport(false)
    setReportData(null)
    wasActive.current = true
    try {
      await startSimulation(10)
      setRunning(true)
      poll()
    } catch (err) {
      setError(err.message)
      wasActive.current = false
    }
  }

  return (
    <div className="min-h-screen bg-gray-950">
      <header className="border-b border-gray-800 bg-gray-900/80 px-6 py-5 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between">
          <div>
            <h1 className="text-xl font-bold tracking-tight">
              Zero-Trust Runtime Threat Simulation
            </h1>
            <p className="text-sm text-gray-400">AI Red Team vs Rule-Based Blue Team</p>
          </div>
          <button
            onClick={handleStart}
            disabled={running}
            className={`rounded-lg px-6 py-2.5 text-sm font-semibold transition ${
              running
                ? 'cursor-not-allowed bg-gray-700 text-gray-400'
                : 'bg-red-600 text-white hover:bg-red-500'
            }`}
          >
            {running
              ? `Running — Round ${status.current_round}/${status.total_rounds}`
              : 'Start Simulation'}
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">
        {error && (
          <div className="mb-4 rounded-lg border border-red-500/50 bg-red-950/30 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-4 text-center">
            <p className="text-2xl font-bold text-attack">{attacks.length}</p>
            <p className="text-xs text-gray-500">Attacks</p>
          </div>
          <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-4 text-center">
            <p className="text-2xl font-bold text-defense">{defenses.length}</p>
            <p className="text-xs text-gray-500">Alerts</p>
          </div>
          <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-4 text-center">
            <p className="text-2xl font-bold text-yellow-400">
              {blocklist.blocked_ips?.length ?? 0}
            </p>
            <p className="text-xs text-gray-500">Blocked IPs</p>
          </div>
          <div className="rounded-lg border border-gray-800 bg-gray-900/50 p-4 text-center">
            <p className="text-2xl font-bold text-green-400">
              {attacks.filter((a) => a.success && !a.blocked).length}
            </p>
            <p className="text-xs text-gray-500">Breaches</p>
          </div>
        </div>

        <BattleView attacks={attacks} defenses={defenses} />
      </main>

      {showReport && reportData && (
        <SimulationReport
          attackLog={reportData.attackLog}
          metrics={reportData.metrics}
          blocklist={reportData.blocklist}
          summary={reportData.summary}
          onClose={() => setShowReport(false)}
        />
      )}
    </div>
  )
}
