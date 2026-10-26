import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { fetchReport } from '../lib/api'
import { formatStatusLabel, formatTimestamp, reportToMarkdown } from '../lib/format'
import type { ReportResponse } from '../types'
import { ApiError } from '../types'
import { SeverityBadge, StatusBadge } from '../components/Badges'
import { EmptyState, ErrorBanner, LoadingState } from '../components/States'

export function ReportPage() {
  const { scanId } = useParams()
  const id = Number(scanId)
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
          setError(loadError instanceof Error ? loadError.message : 'The report could not be loaded.')
        }
        setLoading(false)
      })
    return () => controller.abort()
  }, [id])

  const download = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    anchor.click()
    URL.revokeObjectURL(url)
  }

  if (loading) return <LoadingState label="Loading report…" />
  if (pendingReport) {
    return (
      <EmptyState
        title="Report not ready yet"
        body="The assessment is still running. The report is only available after the scan reaches a terminal status, so partial results are never mistaken for a final report."
        action={
          <Link className="button secondary" to={`/assessment/${id}`}>
            View live progress
          </Link>
        }
      />
    )
  }
  if (error) {
    const missing = error.toLowerCase().includes('not found')
    return (
      <EmptyState
        title={missing ? 'Report not found' : 'Report unavailable'}
        body={error}
        action={
          <Link className="button secondary" to={Number.isNaN(id) ? '/' : `/assessment/${id}`}>
            Return
          </Link>
        }
      />
    )
  }
  if (!report) return <ErrorBanner message="The report response was empty." />

  const severityEntries = Object.entries(report.findings_by_severity)
  const statusEntries = Object.entries(report.findings_by_status)
  const limitations = report.summary?.limitations ?? report.assessment.incomplete_reasons ?? []
  const checks = Object.entries(report.assessment.checks ?? {})

  return (
    <div>
      <header className="page-header">
        <div>
          <p className="kicker">Report</p>
          <h1>{report.summary?.headline ?? `Scan ${report.scan_id}`}</h1>
          <p className="meta">
            {report.target?.name ?? `Target ${report.target_id}`} · {report.target?.base_url ?? 'base URL not recorded'} ·{' '}
            {formatTimestamp(report.completed_at)}
          </p>
        </div>
        <div className="actions">
          <button
            className="button secondary"
            type="button"
            onClick={() =>
              download(JSON.stringify(report, null, 2), `apivigilante-scan-${report.scan_id}.json`, 'application/json')
            }
          >
            Download JSON
          </button>
          <button
            className="button secondary"
            type="button"
            onClick={() => download(reportToMarkdown(report), `apivigilante-scan-${report.scan_id}.md`, 'text/markdown')}
          >
            Download Markdown
          </button>
          <Link className="button primary" to={`/assessment/${id}`}>
            Assessment
          </Link>
        </div>
      </header>

      {report.summary ? (
        <section className="section">
          <div className="summary-panel">
            <h2>{report.summary.headline}</h2>
            <p>{report.summary.verdict}</p>
            <p className="muted">{report.summary.coverage}</p>
            <div className="summary-counts">
              <span>
                <strong>{report.summary.confirmed_findings}</strong> confirmed
              </span>
              <span>
                <strong>{report.summary.candidate_findings}</strong> candidate
              </span>
              <span>
                <strong>{report.total_endpoints}</strong> endpoints
              </span>
            </div>
          </div>
        </section>
      ) : null}

      {!report.assessment.complete || report.status === 'partial' || report.status === 'failed' ? (
        <div className="notice warning">
          <strong>Final status: {formatStatusLabel(report.status)}.</strong> This report is available, but the assessment
          did not finish cleanly.
          {limitations.length ? (
            <ul className="plain-list" style={{ marginTop: 8 }}>
              {limitations.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      <div className="metrics">
        <article className="metric">
          <span>Status</span>
          <strong>{formatStatusLabel(report.status)}</strong>
        </article>
        <article className="metric">
          <span>Endpoints</span>
          <strong>{report.total_endpoints}</strong>
        </article>
        <article className="metric">
          <span>Findings</span>
          <strong>{report.findings_count}</strong>
        </article>
        <article className="metric">
          <span>Classified</span>
          <strong>{report.classification_rate}</strong>
        </article>
      </div>

      <section className="section">
        <div className="split">
          <div className="panel">
            <h2>Severity breakdown</h2>
            {severityEntries.length ? (
              <ul className="plain-list">
                {severityEntries.map(([severity, count]) => (
                  <li key={severity}>
                    <SeverityBadge severity={severity} /> {count}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No findings were persisted, so there is no severity total.</p>
            )}
            {statusEntries.length ? (
              <>
                <h3 style={{ marginTop: 20 }}>By status</h3>
                <ul className="plain-list">
                  {statusEntries.map(([status, count]) => (
                    <li key={status}>
                      <StatusBadge status={status} /> {count}
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
          <div className="panel">
            <h2>Coverage and limitations</h2>
            <p className="muted">{report.summary?.coverage ?? 'Coverage details were not recorded.'}</p>
            {limitations.length ? (
              <ul className="plain-list" style={{ marginTop: 12 }}>
                {limitations.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            ) : (
              <p className="muted" style={{ marginTop: 12 }}>
                No limitations were recorded for this assessment.
              </p>
            )}
          </div>
        </div>
      </section>

      <section className="section">
        <div className="section-heading">
          <h2>Tests performed</h2>
          <p>
            These are the checks the assessment actually attempted. A skipped or unsupported check means that area was
            not covered.
          </p>
        </div>
        {checks.length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Check</th>
                  <th>Status</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {checks.map(([name, value]) => (
                  <tr key={name}>
                    <td>{formatStatusLabel(name)}</td>
                    <td>
                      <StatusBadge status={String(value?.status ?? 'unknown')} />
                    </td>
                    <td>{String(value?.reason ?? value?.note ?? '')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="muted">No check-level outcomes were persisted for this assessment.</p>
        )}
      </section>

      <section className="section">
        <div className="section-heading">
          <h2>Findings</h2>
          <p>Confirmed findings are backed by evidence. Candidate findings need manual review.</p>
        </div>
        {report.findings.length ? (
          report.findings.map((finding) => (
            <article className="finding-card" key={finding.id}>
              <div className="actions">
                <SeverityBadge severity={finding.severity} />
                <StatusBadge status={finding.status} />
              </div>
              <h3>{finding.title ?? finding.description}</h3>
              <p className="meta">
                <span className="method">{finding.endpoint.method?.toUpperCase() ?? '—'}</span>{' '}
                <span className="path">{finding.endpoint.path ?? 'unknown endpoint'}</span> ·{' '}
                {finding.category_label ?? formatStatusLabel(finding.finding_type)}
              </p>
              {finding.what_happened && finding.what_happened !== (finding.title ?? finding.description) ? (
                <p>{finding.what_happened}</p>
              ) : null}
              {finding.remediation ? (
                <p className="muted">
                  <strong>Fix:</strong> {finding.remediation}
                </p>
              ) : null}
              <Link className="linkish" to={`/assessment/${id}/finding/${finding.id}`}>
                Evidence and full detail
              </Link>
            </article>
          ))
        ) : (
          <EmptyState
            title="Zero findings in this report"
            body="The persisted checks did not confirm a vulnerability. Review skipped and unsupported checks before drawing a security conclusion: no findings is not proof of security."
          />
        )}
      </section>

      {report.assessment.failed_stages.length ? (
        <section className="section">
          <h2>Failed stages</h2>
          <ul className="plain-list">
            {report.assessment.failed_stages.map((stage) => (
              <li key={stage}>{formatStatusLabel(stage)}</li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  )
}
