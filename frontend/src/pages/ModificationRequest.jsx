import { useEffect, useState } from 'react'
import { filesAPI, modAPI } from '../services/api'
import StatusBadge from '../components/StatusBadge'
import './ModificationRequest.css'

export default function ModificationRequest() {
  const [files, setFiles]     = useState([])
  const [selected, setSelected] = useState('')
  const [auth, setAuth]         = useState(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const [success, setSuccess]   = useState('')
  const [countdown, setCountdown] = useState(null)

  useEffect(() => {
    filesAPI.list().then((r) => setFiles(r.data)).catch(() => {})
  }, [])

  // Countdown timer for active authorization
  useEffect(() => {
    if (!auth) { setCountdown(null); return }
    const tick = () => {
      const diff = Math.max(0, Math.floor((new Date(auth.expires_at) - Date.now()) / 1000))
      setCountdown(diff)
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [auth])

  async function handleRequest() {
    if (!selected) return
    setLoading(true); setError(''); setSuccess(''); setAuth(null)
    try {
      const res = await modAPI.request(Number(selected))
      setAuth(res.data)
      setSuccess('Modification authorized. You may now edit the file.')
    } catch (err) {
      setError(err.response?.data?.detail || 'Request failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleComplete() {
    if (!auth) return
    setLoading(true)
    try {
      await modAPI.complete(auth.file_id)
      setAuth(null)
      setSuccess('Modification session closed. File is now PROTECTED.')
      setSelected('')
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to close session')
    } finally {
      setLoading(false)
    }
  }

  const selectedFile = files.find((f) => String(f.id) === String(selected))

  return (
    <div>
      <h1 className="page-title">Modification Request</h1>

      <div className="card mod-card">
        <p className="mod-description">
          To modify a protected file, you must go through the trusted modification workflow.
          This creates a short-lived (60-second) authorization window. All changes are logged
          and the file is returned to read-only (PROTECTED) state automatically.
        </p>

        <div className="mod-form">
          <div className="field">
            <label>Select Protected File</label>
            <select value={selected} onChange={(e) => { setSelected(e.target.value); setAuth(null); setError(''); setSuccess('') }}>
              <option value="">— Choose a file —</option>
              {files.map((f) => (
                <option key={f.id} value={f.id} disabled={f.status === 'MISSING'}>
                  {f.filename} [{f.status}]
                </option>
              ))}
            </select>
          </div>

          {selectedFile && (
            <div className="file-info-box">
              <div className="info-row">
                <span>Status</span>
                <StatusBadge type="fileStatus" value={selectedFile.status} />
              </div>
              <div className="info-row">
                <span>Path</span>
                <span className="hash-text">{selectedFile.filepath}</span>
              </div>
              <div className="info-row">
                <span>Baseline SHA-256</span>
                <span className="hash-text">{selectedFile.sha256_hash}</span>
              </div>
            </div>
          )}

          {error   && <div className="error-box">{error}</div>}
          {success && <div className="success-box">{success}</div>}

          {!auth ? (
            <button
              className="btn-primary"
              onClick={handleRequest}
              disabled={!selected || loading}
            >
              {loading ? <span className="spinner" /> : '🔓 Request Modification Access'}
            </button>
          ) : (
            <div className="active-session">
              <div className="session-header">
                <span className="session-badge">ACTIVE MODIFICATION SESSION</span>
                <span className={`countdown ${countdown <= 15 ? 'countdown--urgent' : ''}`}>
                  ⏱ {countdown}s remaining
                </span>
              </div>
              <p className="session-info">
                Write access has been granted. Open and edit the file now, then click "Done".
                The system will detect your change and update the baseline automatically.
              </p>
              <div className="session-details">
                <div className="info-row"><span>Authorization ID</span><span>{auth.id}</span></div>
                <div className="info-row"><span>Expires</span><span>{new Date(auth.expires_at).toLocaleTimeString()}</span></div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
                <button className="btn-success" onClick={handleComplete} disabled={loading}>
                  ✓ Done Editing (Close Session)
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Workflow explanation */}
      <div className="card workflow-card">
        <h2 className="panel-title">How the Modification Workflow Works</h2>
        <ol className="workflow-steps">
          <li><strong>Select</strong> the file you need to modify.</li>
          <li><strong>Request access</strong> – the system creates a 60-second authorization record.</li>
          <li>The file is <strong>temporarily unlocked</strong> (write permission restored).</li>
          <li>Open the file in any editor and <strong>make your changes</strong>.</li>
          <li>The file monitor <strong>detects the change</strong>, verifies the authorization is active, updates the trusted SHA-256 baseline, and <strong>re-locks the file</strong>.</li>
          <li>An <strong>AUTHORIZED_UPDATE</strong> audit event is created.</li>
          <li>If you don't modify the file, click <em>"Done Editing"</em> to close the window early.</li>
        </ol>
        <div className="warning-box">
          ⚠ Any modification made <strong>without</strong> an active authorization will be classified
          as <strong>POSSIBLE TAMPERING</strong> and generate a security alert.
        </div>
      </div>
    </div>
  )
}
