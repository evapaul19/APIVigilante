import type { EndpointCheckResult, InventoryCoverage, ReportResponse, StageOutcome } from '../types'

const COMPLETED_STAGE_STATUSES = new Set([
  'completed',
  'passed',
  'succeeded',
  'built',
  'performed',
  'available',
  'finding_confirmed',
  'candidate',
  'ran_no_finding',
])

const SKIPPED_STAGE_STATUSES = new Set([
  'not_run',
  'not_supported',
  'not_applicable',
  'unsupported',
  'not_requested',
  'skipped',
  'no_endpoints',
])

export function formatStatusLabel(status: string | undefined | null) {
  if (!status) return 'Unknown'
  return status.replace(/_/g, ' ').replace(/\b\w/g, (match) => match.toUpperCase())
}

export function formatTimestamp(value: string | null | undefined) {
  if (!value) return 'Not recorded'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

export function isTerminalStatus(status: string | undefined | null) {
  const normalized = (status ?? '').toLowerCase()
  return normalized === 'completed' || normalized === 'partial' || normalized === 'failed'
}

export function stageTone(status: string | undefined | null) {
  const normalized = (status ?? '').toLowerCase()
  if (normalized === 'failed') return 'danger'
  if (COMPLETED_STAGE_STATUSES.has(normalized)) return 'success'
  if (SKIPPED_STAGE_STATUSES.has(normalized) || normalized === 'partial') return 'warning'
  if (normalized === 'running' || normalized === 'pending') return 'info'
  return 'neutral'
}

export function severityTone(severity: string | undefined | null) {
  const normalized = (severity ?? 'unknown').toLowerCase()
  if (normalized === 'critical' || normalized === 'high') return normalized
  if (normalized === 'medium' || normalized === 'low' || normalized === 'info') return normalized
  return 'unknown'
}

export function getStageEntries(stages: Record<string, StageOutcome> | undefined) {
  return Object.entries(stages ?? {})
}

export function summarizeStages(stages: Record<string, StageOutcome> | undefined) {
  const entries = getStageEntries(stages)
  let completed = 0
  let failed = 0
  let skipped = 0
  let partial = 0
  for (const [, value] of entries) {
    const state = String(value?.status ?? '').toLowerCase()
    if (state === 'partial') partial += 1
    else if (COMPLETED_STAGE_STATUSES.has(state)) completed += 1
    else if (state === 'failed') failed += 1
    else if (SKIPPED_STAGE_STATUSES.has(state)) skipped += 1
  }
  return { total: entries.length, completed, failed, skipped, partial }
}

export function assessmentStateLabel(report: ReportResponse | null, scanStatus?: string) {
  const status = (scanStatus ?? report?.status ?? '').toLowerCase()
  if (status === 'failed') return 'failed'
  if (status === 'partial') return 'incomplete'
  if (status === 'running' || status === 'pending') return 'running'
  if (!report) return status || 'unknown'
  if (!report.assessment.complete && report.assessment.incomplete_reasons.length) return 'incomplete'
  if (report.findings_count === 0) return 'zero-findings'
  return 'findings'
}

const CHECK_KEYS = ['method', 'path', 'outcome', 'check_type', 'rationale', 'inspected', 'finding_id', 'operation_id']

function asResultList(value: unknown): EndpointCheckResult[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is EndpointCheckResult => Boolean(item) && typeof item === 'object')
}

export function collectCheckResults(report: ReportResponse | null): EndpointCheckResult[] {
  if (!report) return []
  const checks = report.assessment.checks ?? {}
  const authorization = (checks.authorization_tests ?? {}) as Record<string, unknown>
  const bola = (checks.bola ?? {}) as Record<string, unknown>
  const bfla = (checks.bfla ?? {}) as Record<string, unknown>
  const sensitive = (checks.sensitive_data ?? {}) as Record<string, unknown>
  const combined = [
    ...asResultList(authorization.results),
    ...asResultList(bola.results),
    ...asResultList(bfla.results),
    ...asResultList(sensitive.results),
  ]
  return combined.map((item) => {
    const next: EndpointCheckResult = {}
    for (const key of CHECK_KEYS) {
      if (key in item) next[key] = item[key]
    }
    if (!next.check_type && item.outcome) next.check_type = 'check'
    return next
  })
}

export function coverageLimitations(coverage: InventoryCoverage | null | undefined) {
  const items: { title: string; issues: { label: string; reason: string }[] }[] = []
  if (!coverage) return items
  const groups: [string, unknown][] = [
    ['Unsupported operations', coverage.unsupported_operations],
    ['Excluded operations', coverage.excluded_operations],
    ['Unresolved parameters', coverage.unresolved_parameters],
    ['Required request bodies', coverage.required_request_bodies],
    ['Execution restrictions', coverage.execution_restrictions],
  ]
  for (const [title, list] of groups) {
    if (!Array.isArray(list) || list.length === 0) continue
    items.push({
      title,
      issues: list.map((issue) => {
        const record = issue as { method?: string; path?: string; reason?: string; parameter?: string }
        const label = [record.method?.toUpperCase(), record.path, record.parameter].filter(Boolean).join(' ')
        return { label: label || 'Operation', reason: record.reason || 'Limitation recorded.' }
      }),
    })
  }
  return items
}

export function reportToMarkdown(report: ReportResponse) {
  const summary = report.summary
  const lines: string[] = [
    `# APIVigilante assessment report`,
    '',
    `- Scan: ${report.scan_id}`,
    `- Target: ${report.target?.name ?? report.target?.base_url ?? report.target_id}`,
    `- Base URL: ${report.target?.base_url ?? 'not recorded'}`,
    `- Final status: ${formatStatusLabel(report.status)}`,
    `- Started: ${formatTimestamp(report.started_at)}`,
    `- Completed: ${formatTimestamp(report.completed_at)}`,
    `- Endpoints inventoried: ${report.total_endpoints}`,
    `- Findings: ${report.findings_count} (${summary?.confirmed_findings ?? 0} confirmed, ${summary?.candidate_findings ?? 0} candidate)`,
    '',
    '## Summary',
    '',
    summary?.headline ?? formatStatusLabel(report.status),
    '',
    summary?.verdict ?? 'The assessment has no plain-language summary.',
    '',
    summary?.coverage ?? '',
    '',
  ]

  const limitations = report.assessment.incomplete_reasons ?? []
  if (limitations.length) {
    lines.push('## Limitations', '')
    for (const reason of limitations) lines.push(`- ${reason}`)
    lines.push('')
  }

  if (Object.keys(report.findings_by_severity).length) {
    lines.push('## Severity breakdown', '')
    for (const [severity, count] of Object.entries(report.findings_by_severity)) {
      lines.push(`- ${formatStatusLabel(severity)}: ${count}`)
    }
    lines.push('')
  }

  lines.push('## Tests performed', '')
  for (const [name, value] of Object.entries(report.assessment.checks ?? {})) {
    const note = value?.reason ?? value?.note
    lines.push(
      `- ${formatStatusLabel(name)}: ${formatStatusLabel(String(value?.status ?? 'unknown'))}${note ? ` — ${String(note)}` : ''}`,
    )
  }
  lines.push('', '## Vulnerabilities found', '')

  if (!report.findings.length) {
    lines.push(
      'No vulnerabilities were confirmed by the checks that ran. This does not prove the target is secure: review the limitations and tests above.',
    )
  } else {
    for (const finding of report.findings) {
      lines.push(
        `### ${finding.title ?? finding.description}`,
        '',
        `- Severity: ${formatStatusLabel(finding.severity)}`,
        `- Status: ${formatStatusLabel(finding.status)}`,
        `- Category: ${finding.category_label ?? formatStatusLabel(finding.finding_type)}`,
        `- Endpoint: ${finding.endpoint.method?.toUpperCase() ?? ''} ${finding.endpoint.path ?? ''}`.trim(),
        `- Confidence: ${finding.confidence ?? 'not recorded'}`,
        '',
        '**What happened:**',
        '',
        finding.what_happened ?? finding.description ?? 'No description was recorded.',
        '',
        '**Why it matters:**',
        '',
        finding.why_it_matters ?? 'No impact rationale was recorded.',
        '',
        '**Impact:**',
        '',
        finding.impact ?? '',
        '',
        `**Severity reasoning:** ${finding.severity_reasoning ?? 'Not recorded.'}`,
        '',
        '**Recommended fix:**',
        '',
        finding.remediation ?? 'No remediation guidance was recorded.',
        '',
        `Evidence records: ${finding.evidence.length} (redacted request/response data is available in the JSON export).`,
        '',
      )
    }
  }

  if (report.assessment.failed_stages?.length) {
    lines.push('## Failed stages', '')
    for (const stage of report.assessment.failed_stages) lines.push(`- ${formatStatusLabel(stage)}`)
    lines.push('')
  }

  return lines.join('\n')
}
