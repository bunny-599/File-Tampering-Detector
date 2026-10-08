/**
 * Reusable badge component that maps status/severity values to CSS classes.
 */

const MAP = {
  fileStatus: {
    PROTECTED:         ['badge-safe',     'PROTECTED'],
    AUTHORIZED_UPDATE: ['badge-auth',     'AUTH UPDATE'],
    TAMPERED:          ['badge-tampered', '⚠ TAMPERED'],
    MISSING:           ['badge-missing',  '✕ MISSING'],
    RECOVERED:         ['badge-safe',     'RECOVERED'],
  },
  alertStatus: {
    OPEN:     ['badge-open',     'OPEN'],
    RESOLVED: ['badge-resolved', 'RESOLVED'],
  },
  severity: {
    CRITICAL: ['badge-critical', 'CRITICAL'],
    HIGH:     ['badge-high',     'HIGH'],
    MEDIUM:   ['badge-medium',   'MEDIUM'],
    LOW:      ['badge-low',      'LOW'],
  },
}

export default function StatusBadge({ type, value }) {
  const entry = MAP[type]?.[value]
  if (!entry) return <span className="badge">{value}</span>
  const [cls, label] = entry
  return <span className={`badge ${cls}`}>{label}</span>
}
