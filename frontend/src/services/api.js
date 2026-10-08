/**
 * Axios API client for SecureFileGuard backend.
 * Automatically attaches the JWT Bearer token from localStorage.
 */

import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

// Attach token to every outbound request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sfg_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Redirect to login on 401
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('sfg_token')
      localStorage.removeItem('sfg_user')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

// ── Auth ────────────────────────────────────────────────────────────────────
export const authAPI = {
  register: (data) => api.post('/auth/register', data),
  login:    (data) => api.post('/auth/login', data),
  logout:   ()     => api.post('/auth/logout'),
  me:       ()     => api.get('/auth/me'),
}

// ── Files ───────────────────────────────────────────────────────────────────
export const filesAPI = {
  list:     ()         => api.get('/files'),
  register: (filepath) => api.post('/files/register', { filepath }),
  get:      (id)       => api.get(`/files/${id}`),
  delete:   (id)       => api.delete(`/files/${id}`),
}

// ── Modifications ────────────────────────────────────────────────────────────
export const modAPI = {
  request:   (fileId) => api.post(`/files/${fileId}/request-modification`),
  authorize: (fileId) => api.post(`/files/${fileId}/authorize-modification`),
  complete:  (fileId, notes) =>
    api.post(`/files/${fileId}/complete-modification`, { notes }),
}

// ── Alerts ───────────────────────────────────────────────────────────────────
export const alertsAPI = {
  list:    (statusFilter) =>
    api.get('/alerts', { params: statusFilter ? { status: statusFilter } : {} }),
  get:     (id)           => api.get(`/alerts/${id}`),
  resolve: (id, notes)    => api.post(`/alerts/${id}/resolve`, { notes }),
}

// ── Audit ────────────────────────────────────────────────────────────────────
export const auditAPI = {
  list:    (limit = 200, offset = 0) =>
    api.get('/audit', { params: { limit, offset } }),
  forFile: (fileId) => api.get(`/audit/${fileId}`),
}

// ── Dashboard ────────────────────────────────────────────────────────────────
export const dashboardAPI = {
  stats: () => api.get('/dashboard/stats'),
}

export default api
