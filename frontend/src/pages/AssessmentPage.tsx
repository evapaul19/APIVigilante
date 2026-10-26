import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { fetchReport, fetchScan } from '../lib/api'
import {
  assessmentStateLabel,
  collectCheckResults,
  coverageLimitations,
  formatStatusLabel,
  formatTimestamp,
  getStageEntries,
  isTerminalStatus,
  summarizeStages,
} from '../lib/format'
import type { ReportResponse, ScanStatusResponse } from '../types'
import { ApiError } from '../types'
import { SeverityBadge, StatusBadge } from '../components/Badges'
import { EmptyState, ErrorBanner, LoadingState } from '../components/States'

export function AssessmentPage() {
  const { scanId } = useParams()
  const id = Number(scanId)
  const [scan, setScan] = useState<ScanStatusResponse | null>(null)
  const [report, setReport] = useState<ReportResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    if (!id || Number.isNaN(id)) {
      setError('The assessment identifier in this URL is invalid.')
      setLoading(false)
      return
    }

    let cancelled = false
    let timer: number | undefined
    let failures = 0
    const controller = new AbortController()

    // Reset state so a different scan id (or an explicit retry) never shows a
    // previous scan's findings.
    setScan(null)
    setReport(null)
    setError('')
    setLoading(true)

    const load = async (): Promise<'poll' | 'stop'> => {
      try {
        const nextScan = await fetchScan(id, { signal: controller.signal })
        if (cancelled) return 'stop'
        setScan(nextScan)
        setError('')
        failures = 0
        if (isTerminalStatus(nextScan.status)) {
          try {
            const nextReport = await fetchReport(id, { signal: controller.signal })
            if (!cancelled) setReport(nextReport)
          } catch (reportError) {
            if (cancelled || (reportError instanceof DOMException && reportError.name === 'AbortError')) return 'stop'
            setError(reportError instanceof Error ? reportError.message : 'The report could not be loaded.')
          }
          setLoading(false)
          return 'stop'
        }
        setLoading(false)
        return 'poll'
      } catch (loadError) {
        if (cancelled || (loadError instanceof DOMException && loadError.name === 'AbortError')) return 'stop'
        failures += 1
        const status = loadError instanceof ApiError ? loadError.status : 0
        setError(loadError instanceof Error ? loadError.message : 'The assessment could not be loaded.')
        setLoading(false)
        if (status === 404 || status === 401 || status === 403 || failures >= 5) return 'stop'
        return 'poll'
      }
    }

    const start = async () => {
      const next = await load()
      if (next === 'poll') {
        timer = window.setInterval(() => {
          void load().then((result) => {
            if (result === 'stop' && timer) window.clearInterval(timer)
          })
        }, 4000)
      }
    }

    void start()
    return () => {
      cancelled = true
      controller.abort()
      if (timer) window.clearInterval(timer)
    }
  }, [id, reloadToken])

  const stages = getStageEntries(report?.assessment.stages)
  const summary = summarizeStages(report?.assessment.stages)
  const checks = collectCheckResults(report)
  const limitations = coverageLimitations(report?.inventory_coverage)
  const state = assessmentStateLabel(report, scan?.status)
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')

  const findings = useMemo(() => {
    const list = report?.findings ?? []
    return list.filter((finding) => {
      const haystack = `${finding.title ?? ''} ${finding.description} ${finding.endpoint.path ?? ''} ${finding.finding_type}`.toLowerCase()
      const matchesQuery = !query || haystack.includes(query.toLowerCase())
      const matchesFilter =
        filter === 'all' || finding.severity === filter || finding.status === filter || finding.finding_type === filter
      return matchesQuery && matchesFilter
    })
  }, [filter, query, report])

  const visibleChecks = useMemo(() => {
    const needle = query.toLowerCase()
    return checks.filter((item) => {
      const haystack = `${item.method ?? ''} ${item.path ?? ''} ${item.outcome ?? ''} ${item.check_type ?? ''}`.toLowerCase()
      return !needle || haystack.includes(needle)
    })
  }, [checks, query])

  if (!id || Number.isNaN(id)) {
    return <ErrorBanner message="The assessment identifier in this URL is invalid." />
  }

  if (loading && !scan && !report) {
    return <LoadingState label="Loading scan status…" />
  }

  return (
    <div>
      <header className="page-header">
        <div>
          <p className="kicker">Assessment {id}</p>
          <h1>{report?.target?.name || report?.target?.base_url || `Scan ${id}`}</h1>
          <p className="meta">{report?.target?.base_url}</p>
        </div>
        <div className="actions">
          {error ? (
            <button className="button secondary" type="button" onClick={() => setReloadToken((value) => value + 1)}>
              Retry
            </button>
          ) : null}
          {isTerminalStatus(scan?.status) ? (
            <Link className="button secondary" to={`/assessment/${id}/report`}>
              Open report
            </Link>
          ) : null}
        </div>
      </header>

      {error ? <ErrorBanner message={error} /> : null}

      <AssessmentTruthBanner state={state} report={report} scan={scan} />

      {report?.summary ? (
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
            {report.summary.limitations.length ? (
              <ul className="plain-list" style={{ marginTop: 12 }}>
                {report.summary.limitations.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            ) : null}
          </div>
        </section>
      ) : null}

      <div className="metrics">
        <article className="metric">
          <span>Status</span>
          <strong>{formatStatusLabel(scan?.status ?? report?.status)}</strong>
        </article>
        <article className="metric">
          <span>Endpoints inventoried</span>
          <strong>{report ? report.total_endpoints : 'Pending'}</strong>
        </article>
        <article className="metric">
          <span>Classified</span>
          <strong>{report ? `${report.classified_endpoints} (${report.classification_rate})` : 'Pending'}</strong>
        </article>
        <article className="metric">
          <span>Findings</span>
          <strong>{report?.findings_count ?? 'Pending'}</strong>
        </article>
      </div>

      <section className="section">
        <div className="split">
          <div className="panel">
            <h2>Lifecycle</h2>
            {scan ? (
              <ul className="plain-list">
                <li>Started: {formatTimestamp(scan.started_at)}</li>
                <li>Completed: {formatTimestamp(scan.completed_at)}</li>
                <li>Target id: {scan.target_id}</li>
              </ul>
            ) : (
              <p className="muted">Waiting for scan status.</p>
            )}
          </div>
          <div className="panel">
            <h2>Persisted stages</h2>
            <p className="meta">
              {summary.completed} completed · {summary.partial} partial · {summary.failed} failed · {summary.skipped}{' '}
              skipped or not run
            </p>
            {stages.length ? (
              <ul className="stage-list">
                {stages.map(([name, value]) => (
                  <li className="stage-item" key={name}>
                    <span>{formatStatusLabel(name)}</span>
                    <StatusBadge status={String(value?.status ?? 'pending')} />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">
                {isTerminalStatus(scan?.status)
                  ? 'No persisted stage records were returned.'
                  : 'Stage results appear as the background assessment runs.'}
              </p>
            )}
          </div>
        </div>
      </section>

      <section className="section">
        <div className="section-heading">
          <h2>Inventory and coverage</h2>
          <p>
            Classification rate measures how many inventoried operations received a risk classification. It is not a
            security score and does not mean every endpoint was tested.
          </p>
        </div>
        {report?.inventory_coverage ? (
          <div className="metrics">
            <article className="metric">
              <span>Discovered</span>
              <strong>{report.inventory_coverage.operations_discovered ?? 0}</strong>
            </article>
            <article className="metric">
              <span>Normalized</span>
              <strong>{report.inventory_coverage.operations_normalized ?? 0}</strong>
            </article>
            <article className="metric">
              <span>Unsupported</span>
              <strong>{report.inventory_coverage.operations_unsupported ?? 0}</strong>
            </article>
            <article className="metric">
              <span>Execution-restricted</span>
              <strong>{report.inventory_coverage.operations_execution_restricted ?? 0}</strong>
            </article>
          </div>
        ) : (
          <p className="muted">
            The report does not include a full endpoint catalog. Coverage counts appear here when recon persisted them.
          </p>
        )}
        {report?.inventory_coverage?.limitations?.length ? (
          <ul className="plain-list">
            {report.inventory_coverage.limitations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : null}
        {limitations.map((group) => (
          <div key={group.title}>
            <h3>{group.title}</h3>
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Operation</th>
                    <th>Limitation</th>
                  </tr>
                </thead>
                <tbody>
                  {group.issues.map((issue) => (
                    <tr key={`${group.title}-${issue.label}-${issue.reason}`}>
                      <td className="path">{issue.label}</td>
                      <td>{issue.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </section>

      <section className="section">
        <div className="section-heading">
          <h2>Checks performed</h2>
          <p>Only operations that appear in authorization or sensitive-data results are listed. Absence means not tested.</p>
        </div>
        <label className="field" style={{ maxWidth: 360 }}>
          <span className="sr-only">Filter operations</span>
          <input
            className="search-input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter by path, method, or outcome"
          />
        </label>
        {visibleChecks.length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Check</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {visibleChecks.map((item, index) => (
                  <tr key={`${item.path}-${item.method}-${item.check_type}-${index}`}>
                    <td className="method">{item.method?.toUpperCase() ?? '—'}</td>
                    <td className="path">{item.path ?? '—'}</td>
                    <td>{formatStatusLabel(String(item.check_type ?? 'check'))}</td>
                    <td>
                      <StatusBadge status={String(item.outcome ?? 'unknown')} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="muted">No per-endpoint check results were included in this report.</p>
        )}
      </section>

      <section className="section">
        <div className="section-heading">
          <h2>Findings</h2>
        </div>
        <div className="toolbar">
          <label>
            Filter
            <select value={filter} onChange={(event) => setFilter(event.target.value)}>
              <option value="all">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
              <option value="confirmed">Confirmed</option>
              <option value="candidate">Candidate</option>
              <option value="bola">BOLA</option>
              <option value="bfla">BFLA</option>
              <option value="sensitive_data">Sensitive data</option>
            </select>
          </label>
        </div>
        {report && report.findings_count === 0 ? (
          <EmptyState
            title="No findings were persisted"
            body="Zero findings means the performed checks did not confirm a vulnerability. It does not mean the target is secure, especially if checks were skipped or incomplete."
          />
        ) : findings.length ? (
          findings.map((finding) => (
            <article className="finding-card" key={finding.id}>
              <div className="actions">
                <SeverityBadge severity={finding.severity} />
                <StatusBadge status={finding.status} />
              </div>
              <h3>{finding.title ?? finding.description ?? 'Finding'}</h3>
              <p className="meta">
                <span className="method">{finding.endpoint.method?.toUpperCase()}</span>{' '}
                <span className="path">{finding.endpoint.path}</span> ·{' '}
                {finding.category_label ?? formatStatusLabel(finding.finding_type)}
                {finding.confidence != null ? ` · confidence ${finding.confidence}` : ''}
              </p>
              <Link className="linkish" to={`/assessment/${id}/finding/${finding.id}`}>
                View evidence and remediation
              </Link>
            </article>
          ))
        ) : (
          <p className="muted">No findings match the current filter.</p>
        )}
      </section>
    </div>
  )
}

function AssessmentTruthBanner({
  state,
  report,
  scan,
}: {
  state: string
  report: ReportResponse | null
  scan: ScanStatusResponse | null
}) {
  if (state === 'running') {
    return (
      <div className="notice">
        This assessment is still {formatStatusLabel(scan?.status)}. Results are not final; this page polls until the scan
        reaches a terminal status.
      </div>
    )
  }
  if (state === 'failed') {
    return (
      <div className="notice warning">
        <strong>The scan is marked failed.</strong> Review the stage errors before treating any inventory as complete. No
        findings are inferred from a failed run.
        {report?.assessment.incomplete_reasons.length ? (
          <ul className="plain-list" style={{ marginTop: 8 }}>
            {report.assessment.incomplete_reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        ) : null}
      </div>
    )
  }
  if (state === 'incomplete') {
    return (
      <div className="notice warning">
        <strong>Incomplete assessment.</strong>
        <p>The assessment finished, but one or more checks failed or could not run.</p>
        {report?.assessment.incomplete_reasons.length ? (
          <ul className="plain-list" style={{ marginTop: 8 }}>
            {report.assessment.incomplete_reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        ) : null}
      </div>
    )
  }
  if (state === 'zero-findings') {
    return (
      <div className="notice">
        The checks performed did not persist a confirmed or candidate finding. This is not an all-clear score.
      </div>
    )
  }
  return null
}
