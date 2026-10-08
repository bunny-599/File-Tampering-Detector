import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authAPI } from '../services/api'
import { saveSession } from '../services/auth'
import './Login.css'

export default function Login() {
  const navigate = useNavigate()
  const [mode, setMode]         = useState('login')   // 'login' | 'register'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole]         = useState('USER')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (mode === 'login') {
        const res = await authAPI.login({ username, password })
        saveSession(res.data.access_token, res.data.user)
        navigate('/dashboard')
      } else {
        await authAPI.register({ username, password, role })
        setMode('login')
        setError('')
        alert('Account created. Please log in.')
      }
    } catch (err) {
      const detail = err.response?.data?.detail
      setError(Array.isArray(detail)
        ? detail.map((d) => d.msg).join(', ')
        : detail || 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <span className="login-icon">🛡️</span>
          <h1>SecureFileGuard</h1>
          <p>File Integrity &amp; Tampering Detection</p>
        </div>

        <div className="login-tabs">
          <button
            className={'tab' + (mode === 'login' ? ' tab--active' : '')}
            onClick={() => { setMode('login'); setError('') }}
          >Login</button>
          <button
            className={'tab' + (mode === 'register' ? ' tab--active' : '')}
            onClick={() => { setMode('register'); setError('') }}
          >Register</button>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="field">
            <label>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              required
              autoComplete="username"
            />
          </div>

          <div className="field">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              required
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            />
          </div>

          {mode === 'register' && (
            <div className="field">
              <label>Role</label>
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="USER">USER</option>
                <option value="ADMIN">ADMIN</option>
              </select>
            </div>
          )}

          {error && <div className="error-box">{error}</div>}

          <button type="submit" className="btn-primary submit-btn" disabled={loading}>
            {loading
              ? <span className="spinner" />
              : mode === 'login' ? 'Sign In' : 'Create Account'}
          </button>
        </form>

        <p className="login-hint">
          Default admin: <code>admin</code> / <code>Admin@1234</code>
        </p>
      </div>
    </div>
  )
}
