/**
 * Auth helper – stores/retrieves the JWT and user object from localStorage.
 * The token is validated server-side on every request; localStorage is only
 * used for convenience (e.g. showing the username without an extra API call).
 */

export function saveSession(token, user) {
  localStorage.setItem('sfg_token', token)
  localStorage.setItem('sfg_user', JSON.stringify(user))
}

export function clearSession() {
  localStorage.removeItem('sfg_token')
  localStorage.removeItem('sfg_user')
}

export function getToken() {
  return localStorage.getItem('sfg_token')
}

export function getUser() {
  try {
    return JSON.parse(localStorage.getItem('sfg_user'))
  } catch {
    return null
  }
}

export function isAuthenticated() {
  return !!getToken()
}
