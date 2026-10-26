import { Link } from 'react-router-dom'
import { EmptyState } from '../components/States'
import { StatusBadge } from '../components/Badges'
import { formatTimestamp } from '../lib/format'
import { loadRecentAssessments } from '../lib/storage'

export function RecentPage() {
  const recent = loadRecentAssessments()

  return (
    <div>
      <header className="page-header">
        <div>
          <p className="kicker">History</p>
          <h1>Recent assessments</h1>
        </div>
        <Link className="button primary" to="/new-assessment">
          New assessment
        </Link>
      </header>
      <p className="muted" style={{ marginBottom: 24, maxWidth: '68ch' }}>
        There is no <code>GET /scans</code> list endpoint on the API. This page shows assessments started in this
        browser only.
      </p>
      {recent.length ? (
        <div className="panel">
          {recent.map((item) => (
            <div className="recent-row" key={item.scan_id}>
              <div>
                <Link className="linkish" to={`/assessment/${item.scan_id}`}>
                  Scan {item.scan_id}
                </Link>
                <p className="meta">
                  {item.target_name || item.base_url} · {formatTimestamp(item.started_at)} ·{' '}
                  {item.mode === 'openapi' ? 'OpenAPI-assisted' : 'Discovery-first'}
                </p>
              </div>
              <StatusBadge status={item.status} />
            </div>
          ))}
        </div>
      ) : (
        <EmptyState
          title="No local assessment history"
          body="Start an assessment to keep a browser-local pointer to its scan identifier."
          action={
            <Link className="button secondary" to="/new-assessment">
              Start assessment
            </Link>
          }
        />
      )}
    </div>
  )
}
