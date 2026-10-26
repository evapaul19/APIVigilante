import { formatStatusLabel, severityTone, stageTone } from '../lib/format'

export function StatusBadge({ status }: { status?: string | null }) {
  return <span className={`badge tone-${stageTone(status)}`}>{formatStatusLabel(status)}</span>
}

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const tone = severityTone(severity)
  return (
    <span className={`badge sev-${tone}`}>
      {formatStatusLabel(severity)} severity
    </span>
  )
}
