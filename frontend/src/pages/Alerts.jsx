import { useEffect, useState, useCallback } from 'react'
import { alertsAPI } from '../services/api'
import StatusBadge from '../components/StatusBadge'
import './Alerts.css'

export default function Alerts() {
  const [alerts, setAlerts]     = useState([])
  const [filter, setFilter]     = useState('OPEN')
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const [expanded, setExpanded] = useState(null)
  const [resolving, setResolving] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await alertsAPI.list(filter || undefined)
      setAlerts(res.data)
      setError('')
    } catch {
      setError('Failed to load alerts')
    } finally {
      setLoading(false)
    }
  }, [filter])

  useEffect(() => { load() }, [load])

  async function handleResolve(id) {
    setResolving(id)
    try {
      await alertsAPI.resolve(id, 'Acknowledged and resolved via dashboard')
      load()
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to resolve')
    } finally {
      setResolving(null)
    }
  }

  function formatMessage(msg) {
    return msg.split('\n').map((line, i) => <div key={i}>{line}</div>)
  }

  return (
    <div>
      <div className="page-header" style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
        <h1 className="page-title" style={{ marginBottom:0 }}>Security Alerts</h1>
        <div style={{ display:'flex', gap:8 }}>
          {['OPEN', 'RESOLVED', ''].map((f) => (
            <button
              key={f}
              className={filter === f ? 'btn-primary' : 'btn-ghost'}
              onClick={() => setFilter(f)}
            >
              {f || 'ALL'}
            </button>
          ))}
          <button className="btn-ghost" onClick={load}>↻</button>
        </div>
      </div>

      {loading
        ? <div style={{ textAlign:'center', padding:40 }}><span className="spinner" /></div>
        : error
          ? <div className="error-box">{error}</div>
          : alerts.length === 0
            ? (
              <div className="card empty-alerts">
                <div className="empty-icon">✅</div>
                <p>No {filter.toLowerCase() || ''} alerts. System is clean.</p>
              </div>
            )
            : (
              <div className="alerts-list">
                {alerts.map((a) => (
                  <div
                    key={a.id}
                    className={`alert-card card ${a.status === 'OPEN' ? 'alert-card--open' : 'alert-card--resolved'}`}
                  >
                    <div className="alert-header" onClick={() => setExpanded(expanded === a.id ? null : a.id)}>
                      <div className="alert-left">
                        <span className="alert-icon">
                          {a.status === 'OPEN' ? '🚨' : '✅'}
                        </span>
                        <div>
                          <div className="alert-type">
                            {a.alert_type.replace(/_/g, ' ')}
                          </div>
                          <div className="alert-time">
                            {new Date(a.timestamp).toLocaleString()}
                          </div>
                        </div>
                      </div>
                      <div style={{ display:'flex', gap:8, alignItems:'center' }}>
                        <StatusBadge type="severity" value={a.severity} />
                        <StatusBadge type="alertStatus" value={a.status} />
                        <span style={{ color:'var(--text-muted)', fontSize:12 }}>
                          {expanded === a.id ? '▲' : '▼'}
                        </span>
                      </div>
                    </div>

                    {expanded === a.id && (
                      <div className="alert-body">
                        <div className="alert-message">
                          {formatMessage(a.message)}
                        </div>
                        {a.status === 'OPEN' && (
                          <button
                            className="btn-ghost resolve-btn"
                            onClick={() => handleResolve(a.id)}
                            disabled={resolving === a.id}
                          >
                            {resolving === a.id
                              ? <span className="spinner" />
                              : '✓ Mark Resolved'}
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )
      }
    </div>
  )
}
