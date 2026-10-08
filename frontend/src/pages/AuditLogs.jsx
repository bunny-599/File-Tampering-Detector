import { useEffect, useState } from 'react'
import { auditAPI } from '../services/api'
import './AuditLogs.css'

const EVENT_COLORS = {
  UNAUTHORIZED_MODIFICATION: 'var(--red)',
  FILE_DELETED:              'var(--red)',
  UNAUTHORIZED_FILE_CREATED: 'var(--red)',
  AUTH_FAILURE:              'var(--yellow)',
  AUTHORIZED_UPDATE:         'var(--green)',
  BASELINE_UPDATED:          'var(--green)',
  PROTECTION_RESTORED:       'var(--green)',
  FILE_REGISTERED:           'var(--accent)',
  MODIFICATION_AUTHORIZED:   'var(--accent)',
  FILE_READ:                 'var(--text-muted)',
}

function EventDot({ type }) {
  const color = EVENT_COLORS[type] || 'var(--text-muted)'
  return (
    <span style={{
      display: 'inline-block',
      width: 8, height: 8,
      borderRadius: '50%',
      background: color,
      marginRight: 6,
      flexShrink: 0,
    }} />
  )
}

export default function AuditLogs() {
  const [logs, setLogs]     = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState('')
  const [expanded, setExpanded] = useState(null)
  const [page, setPage]     = useState(0)
  const PAGE_SIZE = 50

  async function load(offset = 0) {
    setLoading(true)
    try {
      const res = await auditAPI.list(PAGE_SIZE, offset)
      setLogs(res.data)
      setError('')
    } catch {
      setError('Failed to load audit logs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load(page * PAGE_SIZE) }, [page])

  function shortHash(h) {
    return h ? h.slice(0, 12) + '…' : null
  }

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
        <h1 className="page-title" style={{ marginBottom:0 }}>Audit Logs</h1>
        <button className="btn-ghost" onClick={() => load(page * PAGE_SIZE)}>↻ Refresh</button>
      </div>

      {loading
        ? <div style={{ textAlign:'center', padding:40 }}><span className="spinner" /></div>
        : error
          ? <div className="error-box">{error}</div>
          : (
            <>
              <div className="card" style={{ overflowX:'auto' }}>
                {logs.length === 0
                  ? <p style={{ color:'var(--text-muted)', padding:'12px 0' }}>No audit events yet.</p>
                  : (
                    <table>
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Event</th>
                          <th>File</th>
                          <th>User</th>
                          <th>Hashes</th>
                          <th>Time</th>
                        </tr>
                      </thead>
                      <tbody>
                        {logs.map((log) => (
                          <>
                            <tr
                              key={log.id}
                              onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                              style={{ cursor: 'pointer' }}
                            >
                              <td style={{ color:'var(--text-muted)', fontSize:11 }}>{log.id}</td>
                              <td>
                                <div style={{ display:'flex', alignItems:'center' }}>
                                  <EventDot type={log.event_type} />
                                  <span style={{ fontSize:12, fontWeight:500 }}>
                                    {log.event_type.replace(/_/g, ' ')}
                                  </span>
                                </div>
                              </td>
                              <td style={{ color:'var(--text-muted)', fontSize:12 }}>
                                {log.file_id ?? '—'}
                              </td>
                              <td style={{ color:'var(--text-muted)', fontSize:12 }}>
                                {log.user_id ?? 'system'}
                              </td>
                              <td>
                                {log.old_hash && (
                                  <span className="hash-text">
                                    {shortHash(log.old_hash)} → {shortHash(log.new_hash) ?? '—'}
                                  </span>
                                )}
                              </td>
                              <td style={{ color:'var(--text-muted)', fontSize:11, whiteSpace:'nowrap' }}>
                                {new Date(log.timestamp).toLocaleString()}
                              </td>
                            </tr>
                            {expanded === log.id && (
                              <tr key={`${log.id}-detail`}>
                                <td colSpan={6} className="audit-detail-row">
                                  <div className="audit-detail">
                                    {log.details && (
                                      <div><strong>Details:</strong> {log.details}</div>
                                    )}
                                    {log.old_hash && (
                                      <div><strong>Old hash:</strong> <span className="hash-text">{log.old_hash}</span></div>
                                    )}
                                    {log.new_hash && (
                                      <div><strong>New hash:</strong> <span className="hash-text">{log.new_hash}</span></div>
                                    )}
                                    {log.os_user && (
                                      <div><strong>OS user:</strong> {log.os_user}</div>
                                    )}
                                    {log.process_name && (
                                      <div><strong>Process:</strong> {log.process_name}</div>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </>
                        ))}
                      </tbody>
                    </table>
                  )
                }
              </div>

              {/* Pagination */}
              <div style={{ display:'flex', gap:8, marginTop:16, justifyContent:'flex-end' }}>
                <button
                  className="btn-ghost"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                >← Prev</button>
                <span style={{ alignSelf:'center', color:'var(--text-muted)', fontSize:12 }}>
                  Page {page + 1}
                </span>
                <button
                  className="btn-ghost"
                  onClick={() => setPage((p) => p + 1)}
                  disabled={logs.length < PAGE_SIZE}
                >Next →</button>
              </div>
            </>
          )
      }
    </div>
  )
}
