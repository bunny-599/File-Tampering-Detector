import { useEffect, useState, useCallback } from 'react'
import { dashboardAPI } from '../services/api'
import StatusBadge from '../components/StatusBadge'
import './Dashboard.css'

function StatCard({ label, value, color }) {
  return (
    <div className="stat-card" style={{ '--accent-color': color }}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats]   = useState(null)
  const [error, setError]   = useState('')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const res = await dashboardAPI.stats()
      setStats(res.data)
      setError('')
    } catch {
      setError('Failed to load dashboard stats')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, 10000)   // auto-refresh every 10 s
    return () => clearInterval(id)
  }, [load])

  if (loading) return <div style={{ padding: 40, textAlign: 'center' }}><span className="spinner" /></div>
  if (error)   return <div className="error-box" style={{ margin: 20 }}>{error}</div>
  if (!stats)  return null

  return (
    <div className="dashboard">
      <div className="page-header">
        <h1 className="page-title">Security Dashboard</h1>
        <button className="btn-ghost" onClick={load}>↻ Refresh</button>
      </div>

      {/* ── Stat cards ── */}
      <div className="stat-grid">
        <StatCard label="Total Protected"      value={stats.total_protected}          color="var(--accent)" />
        <StatCard label="Safe Files"           value={stats.safe_files}               color="var(--green)"  />
        <StatCard label="Tampering Alerts"     value={stats.tampered_files}           color="var(--red)"    />
        <StatCard label="Missing Files"        value={stats.missing_files}            color="var(--yellow)" />
        <StatCard label="Auth Updates"         value={stats.authorized_updates}       color="var(--accent)" />
        <StatCard label="Open Alerts"          value={stats.open_alerts}              color="var(--red)"    />
        <StatCard label="Active Mod Sessions"  value={stats.active_modification_sessions} color="var(--orange)" />
      </div>

      <div className="dashboard-panels">
        {/* ── Recent alerts ── */}
        <div className="card panel">
          <h2 className="panel-title">Recent Alerts</h2>
          {stats.recent_alerts.length === 0
            ? <p className="empty-state">No alerts. All files are safe.</p>
            : (
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Time</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent_alerts.map((a) => (
                    <tr key={a.id}>
                      <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {a.alert_type.replace(/_/g, ' ')}
                      </td>
                      <td><StatusBadge type="severity" value={a.severity} /></td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                        {new Date(a.timestamp).toLocaleString()}
                      </td>
                      <td><StatusBadge type="alertStatus" value={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </div>

        {/* ── Recent audit ── */}
        <div className="card panel">
          <h2 className="panel-title">Recent Audit Events</h2>
          {stats.recent_audit.length === 0
            ? <p className="empty-state">No audit events yet.</p>
            : (
              <table>
                <thead>
                  <tr>
                    <th>Event</th>
                    <th>Time</th>
                    <th>User</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent_audit.map((e) => (
                    <tr key={e.id}>
                      <td>{e.event_type.replace(/_/g, ' ')}</td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>
                        {e.user_id ?? '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </div>
      </div>
    </div>
  )
}
