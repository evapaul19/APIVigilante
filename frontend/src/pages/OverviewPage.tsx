import { Link } from 'react-router-dom'
import { loadRecentAssessments } from '../lib/storage'
import { formatStatusLabel, formatTimestamp } from '../lib/format'
import { StatusBadge } from '../components/Badges'

const capabilities = [
  ['Discovery', 'Inventory documented operations or use bounded same-origin HTML-link discovery when no spec is available.'],
  ['OpenAPI-assisted', 'Supply a specification URL when you know where the contract lives.'],
  ['Discovery-first', 'Probe known OpenAPI locations, then inspect a bounded set of linked pages. Unlinked API routes may remain undiscovered.'],
  ['Authorization', 'Run BOLA and BFLA checks only when active testing is approved and the target is authorized.'],
  ['Sensitive data', 'Inspect responses for sensitive-data disclosure after identity and budget gates pass.'],
  ['Evidence', 'Review redacted request and response evidence attached to persisted findings.'],
  ['Reporting', 'Read stage-aware reports that distinguish skipped, unsupported, failed, and completed checks.'],
]

export function OverviewPage() {
  const recent = loadRecentAssessments()

  return (
    <div>
      <section className="hero hero-immersive">
        <div className="hero-copy">
          <p className="kicker">API security intelligence</p>
          <h1>See what your API exposes.</h1>
          <p className="lede">
            Assess authorized API surfaces, inspect evidence-backed findings, and understand exactly which checks ran
            and where coverage ends.
          </p>
          <div className="actions">
            <Link className="button primary" to="/new-assessment">
              Start assessment
            </Link>
            <Link className="button secondary" to="/recent">
              Recent assessments
            </Link>
          </div>
        </div>
        <div className="pipeline-panel" aria-label="Assessment workflow overview">
          <div className="pipeline-heading">
            <span className="pipeline-lights" aria-hidden="true"><span /><span /><span /></span>
            <span>APIVIGILANTE / WORKFLOW</span>
          </div>
          <div className="pipeline-body">
            <p className="pipeline-command"><span>$</span> assessment --authorized-target</p>
            <ol className="pipeline-stages">
              <li>validate target scope</li>
              <li>inventory documented or linked routes</li>
              <li>run eligible security checks</li>
              <li>persist evidence and coverage</li>
            </ol>
          </div>
          <div className="pipeline-footer" aria-label="Workflow stages">
            <span>Inventory</span>
            <span>Assessment</span>
            <span>Evidence</span>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="section-heading">
          <h2>What this platform actually does</h2>
          <p>
            APIVigilante is a staged assessment service. Discovery is not the same as testing. Findings are produced
            only when a check runs and records evidence.
          </p>
        </div>
        <dl className="capability-list">
          {capabilities.map(([title, copy]) => (
            <div className="capability" key={title}>
              <dt>{title}</dt>
              <dd>{copy}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="section">
        <div className="section-heading">
          <h2>Assessments started in this browser</h2>
          <p>
            The backend does not expose a scan-history list. This list is stored locally after you start an assessment
            here and is not a complete server inventory.
          </p>
        </div>
        {recent.length ? (
          <div>
            {recent.slice(0, 5).map((item) => (
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
                <StatusBadge status={formatStatusLabel(item.status)} />
              </div>
            ))}
          </div>
        ) : (
          <p className="muted">No assessments have been started from this browser yet.</p>
        )}
      </section>
    </div>
  )
}
