import { useEffect, useState } from 'react'
import { filesAPI, modAPI } from '../services/api'
import { getUser } from '../services/auth'
import StatusBadge from '../components/StatusBadge'
import './ProtectedFiles.css'

export default function ProtectedFiles() {
  const [files, setFiles]     = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [newPath, setNewPath] = useState('')
  const [registering, setRegistering] = useState(false)
  const [regError, setRegError]   = useState('')
  const [regSuccess, setRegSuccess] = useState('')
  const [actionMsg, setActionMsg] = useState({})
  const user = getUser()

  async function load() {
    try {
      const res = await filesAPI.list()
      setFiles(res.data)
      setError('')
    } catch {
      setError('Failed to load files')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function handleRegister(e) {
    e.preventDefault()
    setRegError(''); setRegSuccess(''); setRegistering(true)
    try {
      await filesAPI.register(newPath.trim())
      setNewPath('')
      setRegSuccess('File registered successfully.')
      load()
    } catch (err) {
      const d = err.response?.data?.detail
      setRegError(d || 'Registration failed')
    } finally {
      setRegistering(false)
    }
  }

  async function handleRequestMod(fileId) {
    setActionMsg((m) => ({ ...m, [fileId]: { type: 'loading', text: 'Requesting…' } }))
    try {
      const res = await modAPI.request(fileId)
      const exp = new Date(res.data.expires_at).toLocaleTimeString()
      setActionMsg((m) => ({
        ...m,
        [fileId]: { type: 'success', text: `Write access granted. Expires at ${exp}` },
      }))
      load()
    } catch (err) {
      const d = err.response?.data?.detail
      setActionMsg((m) => ({ ...m, [fileId]: { type: 'error', text: d || 'Failed' } }))
    }
  }

  async function handleCompleteMod(fileId) {
    setActionMsg((m) => ({ ...m, [fileId]: { type: 'loading', text: 'Closing session…' } }))
    try {
      await modAPI.complete(fileId)
      setActionMsg((m) => ({
        ...m,
        [fileId]: { type: 'success', text: 'Modification session closed. File is PROTECTED.' },
      }))
      load()
    } catch (err) {
      const d = err.response?.data?.detail
      setActionMsg((m) => ({ ...m, [fileId]: { type: 'error', text: d || 'Failed' } }))
    }
  }

  async function handleDelete(fileId) {
    if (!confirm('Unregister this file from monitoring? The physical file will NOT be deleted.')) return
    try {
      await filesAPI.delete(fileId)
      load()
    } catch (err) {
      alert(err.response?.data?.detail || 'Deletion failed')
    }
  }

  function shortHash(h) { return h ? h.slice(0, 16) + '…' : '—' }

  return (
    <div>
      <h1 className="page-title">Protected Files</h1>

      {/* ── Register form ── */}
      <div className="card register-card">
        <h2 className="panel-title">Register New File</h2>
        <form onSubmit={handleRegister} className="register-form">
          <input
            type="text"
            value={newPath}
            onChange={(e) => setNewPath(e.target.value)}
            placeholder="Absolute path, e.g. C:\projects\protected_files\report.txt"
            required
          />
          <button type="submit" className="btn-primary" disabled={registering}>
            {registering ? <span className="spinner" /> : '+ Register'}
          </button>
        </form>
        {regError   && <div className="error-box"   style={{ marginTop: 10 }}>{regError}</div>}
        {regSuccess && <div className="success-box" style={{ marginTop: 10 }}>{regSuccess}</div>}
      </div>

      {/* ── Files table ── */}
      {loading
        ? <div style={{ textAlign: 'center', padding: 40 }}><span className="spinner" /></div>
        : error
          ? <div className="error-box">{error}</div>
          : (
            <div className="card" style={{ marginTop: 20, overflowX: 'auto' }}>
              {files.length === 0
                ? <p style={{ color: 'var(--text-muted)', padding: '12px 0' }}>
                    No files registered. Register a file above to begin monitoring.
                  </p>
                : (
                  <table>
                    <thead>
                      <tr>
                        <th>File</th>
                        <th>Status</th>
                        <th>SHA-256 (baseline)</th>
                        <th>Size</th>
                        <th>Last Checked</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.map((f) => (
                        <tr key={f.id}>
                          <td>
                            <div style={{ fontWeight: 600 }}>{f.filename}</div>
                            <div style={{ color: 'var(--text-muted)', fontSize: 11, wordBreak: 'break-all' }}>
                              {f.filepath}
                            </div>
                          </td>
                          <td><StatusBadge type="fileStatus" value={f.status} /></td>
                          <td><span className="hash-text">{shortHash(f.sha256_hash)}</span></td>
                          <td style={{ color: 'var(--text-muted)' }}>
                            {f.file_size != null ? `${f.file_size} B` : '—'}
                          </td>
                          <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                            {f.last_checked ? new Date(f.last_checked).toLocaleString() : '—'}
                          </td>
                          <td>
                            <div className="action-cell">
                              {f.status === 'AUTHORIZED_UPDATE' ? (
                                <button
                                  className="btn-ghost"
                                  onClick={() => handleCompleteMod(f.id)}
                                >
                                  Done Editing
                                </button>
                              ) : (
                                <button
                                  className="btn-primary"
                                  onClick={() => handleRequestMod(f.id)}
                                  disabled={f.status === 'MISSING'}
                                >
                                  Request Mod
                                </button>
                              )}
                              {user?.role === 'ADMIN' && (
                                <button
                                  className="btn-danger"
                                  onClick={() => handleDelete(f.id)}
                                  style={{ marginLeft: 6 }}
                                >
                                  ✕
                                </button>
                              )}
                            </div>
                            {actionMsg[f.id] && (
                              <div
                                className={
                                  actionMsg[f.id].type === 'error'
                                    ? 'error-box'
                                    : actionMsg[f.id].type === 'success'
                                      ? 'success-box'
                                      : ''
                                }
                                style={{ marginTop: 6, fontSize: 11 }}
                              >
                                {actionMsg[f.id].text}
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )
              }
            </div>
          )
      }
    </div>
  )
}
