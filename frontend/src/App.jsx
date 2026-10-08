import { Routes, Route, Navigate } from 'react-router-dom'
import { isAuthenticated } from './services/auth'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import ProtectedFiles from './pages/ProtectedFiles'
import ModificationRequest from './pages/ModificationRequest'
import Alerts from './pages/Alerts'
import AuditLogs from './pages/AuditLogs'

function RequireAuth({ children }) {
  return isAuthenticated() ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard"     element={<Dashboard />} />
        <Route path="files"         element={<ProtectedFiles />} />
        <Route path="modifications" element={<ModificationRequest />} />
        <Route path="alerts"        element={<Alerts />} />
        <Route path="audit"         element={<AuditLogs />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
