import type { ReportResponse } from '../types'

export const completedReport: ReportResponse = {
  scan_id: 12,
  target_id: 3,
  target: { id: 3, name: 'Local test API', base_url: 'http://127.0.0.1:5001' },
  spec_source: 'http://127.0.0.1:5001/openapi.json',
  status: 'completed',
  started_at: '2026-10-25T12:00:00Z',
  completed_at: '2026-10-25T12:01:00Z',
  total_endpoints: 8,
  classified_endpoints: 8,
  classification_rate: '100.0%',
  findings_count: 1,
  findings_by_severity: { high: 1 },
  findings_by_status: { confirmed: 1 },
  findings_by_type: { bola: 1 },
  findings: [
    {
      id: 44,
      finding_type: 'bola',
      severity: 'high',
      status: 'confirmed',
      confidence: 0.9,
      description: 'Cross-identity access succeeded on GET /users/{user_id}.',
      endpoint: { id: 9, method: 'GET', path: '/users/{user_id}', operation_id: 'get_user' },
      evidence: [
        {
          execution_id: 70,
          response_status: 200,
          request_headers: { Authorization: '***REDACTED***' },
          request_body: null,
          response_headers: {},
          response_body: { username: 'victim' },
          executed_at: '2026-10-25T12:00:40Z',
        },
      ],
    },
  ],
  resource_graph_summary: { resources: ['user'], endpoint_count: 8, edge_count: 4 },
  inventory_coverage: {
    operations_discovered: 10,
    operations_normalized: 8,
    operations_unsupported: 1,
    operations_execution_restricted: 1,
    limitations: ['HEAD operations are not executed.'],
    unsupported_operations: [{ method: 'TRACE', path: '/debug', reason: 'Method is not supported.' }],
  },
  findings_populated: true,
  has_classified_endpoints: true,
  zero_or_incomplete: { zero_findings: false, no_classified_endpoints: false, classification_rate: '100.0%' },
  assessment: {
    complete: true,
    status: 'completed',
    stages_persisted: true,
    stage_source: 'persisted',
    stages: {
      target_validation: { status: 'passed' },
      spec_discovery: { status: 'succeeded' },
      recon: { status: 'completed' },
      classification: { status: 'completed' },
      resource_graph: { status: 'built' },
      authorization_checks: { status: 'performed' },
      sensitive_data_checks: { status: 'performed' },
      persistence: { status: 'completed' },
      report: { status: 'available' },
    },
    failed_stages: [],
    incomplete_reasons: [],
    checks: {
      recon: { status: 'completed' },
      authorization_tests: { status: 'performed' },
      bola: {
        status: 'finding_confirmed',
        results: [{ method: 'GET', path: '/users/{user_id}', outcome: 'confirmed', check_type: 'bola' }],
      },
      bfla: { status: 'ran_no_finding', results: [] },
      sensitive_data: {
        status: 'performed',
        results: [{ method: 'GET', path: '/users', outcome: 'ruled_out', check_type: 'sensitive_data' }],
      },
    },
  },
}

export const zeroFindingReport: ReportResponse = {
  ...completedReport,
  findings_count: 0,
  findings: [],
  findings_by_severity: {},
  findings_by_status: {},
  findings_by_type: {},
  findings_populated: false,
  zero_or_incomplete: { zero_findings: true, no_classified_endpoints: false, classification_rate: '100.0%' },
  assessment: {
    ...completedReport.assessment,
    checks: {
      ...completedReport.assessment.checks,
      bola: { status: 'ran_no_finding', results: [] },
    },
  },
}

export const incompleteReport: ReportResponse = {
  ...zeroFindingReport,
  assessment: {
    ...zeroFindingReport.assessment,
    complete: false,
    incomplete_reasons: ['Identity registration was not approved.'],
    checks: {
      recon: { status: 'completed' },
      authorization_tests: { status: 'not_run', reason: 'Identity registration was not approved.' },
    },
  },
}

export const failedScan = {
  id: 12,
  target_id: 3,
  status: 'failed',
  started_at: '2026-10-25T12:00:00Z',
  completed_at: '2026-10-25T12:00:20Z',
}

export const partialReport: ReportResponse = {
  ...completedReport,
  status: 'partial',
  findings_count: 2,
  findings_by_status: { confirmed: 1, candidate: 1 },
  findings_by_type: { bola: 1, sensitive_data: 1 },
  findings_by_severity: { high: 1, medium: 1 },
  summary: {
    headline: 'Assessment completed with limitations',
    verdict:
      'The assessment finished and produced results, but one or more checks failed or could not be completed. Review the limitations before drawing conclusions about the target.',
    coverage: '8 endpoint(s) were inventoried. Discovery is bounded: endpoints that are neither documented nor linked may not appear.',
    confirmed_findings: 1,
    candidate_findings: 1,
    limitations: ['Sensitive-data checks failed.'],
  },
  findings: [
    {
      ...completedReport.findings[0],
      title: 'Broken object-level authorization on GET /users/{user_id}',
      category_label: 'Broken object-level authorization',
      what_happened: 'Cross-identity access succeeded on GET /users/{user_id}.',
      why_it_matters: 'An authenticated caller may be able to read another user’s data.',
      impact: 'Confirmed weakness until it is fixed and retested.',
      remediation: 'Enforce object ownership checks on every identifier-based request.',
      severity_reasoning: 'Rated high because the behavior crosses a security boundary.',
    },
    {
      id: 45,
      finding_type: 'sensitive_data',
      severity: 'medium',
      status: 'candidate',
      confidence: 0.5,
      description: 'Possible sensitive data exposure on GET /users.',
      title: 'Possible sensitive data exposure on GET /users (unconfirmed)',
      category_label: 'Sensitive data exposure',
      what_happened: 'The response contained fields that may be sensitive.',
      why_it_matters: 'Responses may disclose personal data to a wider audience than intended.',
      impact: 'Lead for manual review, not a confirmed vulnerability.',
      remediation: 'Return only required fields.',
      severity_reasoning: 'Rated medium because evidence is indirect.',
      endpoint: { id: 10, method: 'GET', path: '/users', operation_id: 'list_users' },
      evidence: [],
    },
  ],
  assessment: {
    ...completedReport.assessment,
    complete: false,
    status: 'partial',
    failed_stages: ['sensitive_data_checks'],
    incomplete_reasons: ['Sensitive-data checks failed.'],
  },
}
