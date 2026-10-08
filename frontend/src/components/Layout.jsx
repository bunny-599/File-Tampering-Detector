import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { getUser, clearSession } from '../services/auth'
import { authAPI } from '../services/api'
import './Layout.css'

const NAV = [
  { to: '/dashboard',     icon: '⬛', label: 'Dashboard'     },
  { to: '/files',         icon: '🗂️', label: 'Protected Files' },
  { to: '/modifications', icon: '✏️',  label: 'Modifications'  },
  { to: '/alerts',        icon: '🚨', label: 'Alerts'         },
  { to: '/audit',         icon: '📋', label: 'Audit Logs'     },
]

export default function Layout() {
  const navigate = useNavigate()
  const user = getUser()

  async function handleLogout() {
    try { await authAPI.logout() } catch {}
    clearSession()
    navigate('/login')
  }

  return (
    <div className="layout">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-icon">🛡️</span>
          <span className="brand-name">SecureFileGuard</span>
        </div>

        <nav className="sidebar-nav">
          {NAV.map(({ to, icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                'nav-item' + (isActive ? ' nav-item--active' : '')
              }
            >
              <span className="nav-icon">{icon}</span>
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="user-info">
            <span className="user-avatar">{user?.username?.[0]?.toUpperCase() ?? '?'}</span>
            <div>
              <div className="user-name">{user?.username}</div>
              <div className="user-role">{user?.role}</div>
            </div>
          </div>
          <button className="btn-ghost logout-btn" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  )
}
