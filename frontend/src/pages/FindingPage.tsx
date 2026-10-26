import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { fetchReport } from '../lib/api'
import { formatStatusLabel, formatTimestamp } from '../lib/format'
import type { ReportResponse } from '../types'
import { ApiError } from '../types'
import { SeverityBadge, StatusBadge } from '../components/Badges'
import { EmptyState, ErrorBanner, LoadingState } from '../components/States'

export function FindingPage() {
  const { scanId, findingId } = useParams()
  const id = Number(scanId)
  const findingNumber = Number(findingId)
  const [report, setReport] = useState<ReportResponse | null>(null)
  const [error, setError] = useState('')
  const [pendingReport, setPendingReport] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (Number.isNaN(id)) {
      setError('Invalid assessment identifier.')
      setLoading(false)
      return
    }
    setReport(null)
    setError('')
    setPendingReport(false)
    setLoading(true)
    const controller = new AbortController()
    fetchReport(id, { signal: controller.signal })
      .then((next) => {
        setReport(next)
        setLoading(false)
      })
      .catch((loadError: unknown) => {
        if (loadError instanceof DOMException && loadError.name === 'AbortError') return
        if (loadError instanceof ApiError && loadError.status === 409) {
          setPendingReport(true)
        } else {
          setError(loadError instanceof Error ? loadError.message : 'Finding data could not be loaded.')
        }
        setLoading(false)
      })
    return () => controller.abort()
  }, [id])

  const finding = report?.findings.find((entry) => entry.id === findingNumber) ?? null

  if (loading) return <LoadingState label="Loading finding…" />
  if (pendingReport) {
    return (
      <EmptyState
        title="Results are not final yet"
        body="The assessment is still running, so this finding's evidence is not available. The report becomes readable when the scan finishes."
        action={
          <Link className="button secondary" to={`/assessment/${id}`}>
            View live progress
          </Link>
        }
      />
    )
  }
  if (error) {
    return (
      <>
        <ErrorBanner message={error} />
        <Link className="button secondary" to={`/assessment/${id}`}>
          Back to assessment
        </Link>
      </>
    )
  }
  if (!finding) {
    return (
      <EmptyState
        title="Finding not found"
        body="This identifier is not present in the persisted report. It may belong to a different scan."
        action={
          <Link className="button secondary" to={`/assessment/${id}`}>
            Back to assessment
          </Link>
        }
      />
    )
  }

  return (
    <div>
      <header className="page-header">
        <div>
          <p className="kicker">Finding {finding.id}</p>
          <h1>{finding.title ?? finding.description ?? 'Assessment finding'}</h1>
          <p className="meta">
            <span className="method">{finding.endpoint.method?.toUpperCase() ?? '—'}</span>{' '}
            <span className="path">{finding.endpoint.path ?? 'unknown endpoint'}</span>
          </p>
        </div>
        <div className="actions">
          <Link className="button secondary" to={`/assessment/${id}/report`}>
            Full report
          </Link>
          <Link className="button secondary" to={`/assessment/${id}`}>
            Back to assessment
          </Link>
        </div>
      </header>

      <div className="split">
        <div className="panel">
          <div className="actions">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
          </div>
          <dl className="dl" style={{ marginTop: 16 }}>
            <div>
              <dt>Category</dt>
              <dd>{finding.category_label ?? formatStatusLabel(finding.finding_type)}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>{formatStatusLabel(finding.status)}</dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd>{finding.confidence ?? 'Not provided'}</dd>
            </div>
            <div>
              <dt>Operation id</dt>
              <dd>{finding.endpoint.operation_id ?? 'Not recorded'}</dd>
            </div>
          </dl>
        </div>

        <div className="panel">
          <h2>Why this severity</h2>
          <p>{finding.severity_reasoning ?? 'No severity rationale was recorded for this finding.'}</p>
          <h2 style={{ marginTop: 20 }}>What this status means</h2>
          <p className="muted">{statusMeaning(finding.status)}</p>
        </div>
      </div>

      <section className="section">
        <div className="detail-grid">
          <article className="detail-card">
            <h2>What happened</h2>
            <p>{finding.what_happened ?? finding.description ?? 'No description was recorded.'}</p>
          </article>
          <article className="detail-card">
            <h2>Why it matters</h2>
            <p>{finding.why_it_matters ?? 'No impact rationale was recorded.'}</p>
          </article>
          <article className="detail-card">
            <h2>Impact</h2>
            <p>{finding.impact ?? 'No impact statement was recorded.'}</p>
          </article>
          <article className="detail-card accent">
            <h2>How to fix it</h2>
            <p>{finding.remediation ?? 'No remediation guidance was recorded.'}</p>
          </article>
        </div>
      </section>

      <section className="section">
        <div className="section-heading">
          <h2>Evidence</h2>
          <p>
            Only the request and response data the backend persisted after redaction is shown. Secrets and sensitive
            headers are removed before storage.
          </p>
        </div>
        {finding.evidence.length ? (
          <div className="evidence">
            {finding.evidence.map((entry) => (
              <div className="panel" key={entry.execution_id}>
                <p className="meta">
                  Execution {entry.execution_id}
                  {entry.response_status != null ? ` · HTTP ${entry.response_status}` : ''}
                  {entry.executed_at ? ` · ${formatTimestamp(entry.executed_at)}` : ''}
                </p>
                <pre className="code">
                  {JSON.stringify(
                    {
                      request_headers: entry.request_headers,
                      request_body: entry.request_body,
                      response_headers: entry.response_headers,
                      response_body: entry.response_body,
                    },
                    null,
                    2,
                  )}
                </pre>
              </div>
            ))}
          </div>
        ) : (
          <p className="muted">No evidence records were attached to this finding.</p>
        )}
      </section>
    </div>
  )
}

function statusMeaning(status: string) {
  switch (status.toLowerCase()) {
    case 'confirmed':
      return 'A test ran and produced deterministic evidence that the behavior is reachable. Treat it as a weakness until it is fixed and retested.'
    case 'candidate':
      return 'A test observed something suspicious, but the evidence is indirect. Review it manually; it is not proof of a vulnerability.'
    default:
      return 'This record is retained for traceability. Its status does not by itself establish that the target is vulnerable.'
  }
}
