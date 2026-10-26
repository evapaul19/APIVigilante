export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'

export type AssessmentMode = 'openapi' | 'discovery'

export type AuthProfileType = 'static' | 'login' | 'none'
export type AuthScheme = 'bearer' | 'api_key' | 'basic' | 'custom'

export interface AuthIdentityForm {
  id: string
  label: string
  username: string
  password: string
  token: string
  api_key: string
  subject: string
  admin: boolean
}

export interface AuthProfileForm {
  enabled: boolean
  type: AuthProfileType
  scheme: AuthScheme
  header_name: string
  token_prefix: string
  login_path: string
  login_username_field: string
  login_password_field: string
  token_path: string
  identities: AuthIdentityForm[]
}

export interface AssessmentFormState {
  mode: AssessmentMode
  base_url: string
  openapi_spec_url: string
  target_name: string
  allow_identity_registration: boolean
  authorized_for_active_testing: boolean
  classify: boolean
  request_budget: number
  authorization_confirmed: boolean
  auth_profile: AuthProfileForm
}

export interface AuthIdentityPayload {
  label: string
  username?: string
  password?: string
  token?: string
  api_key?: string
  subject?: string
  admin?: boolean
}

export interface AuthProfilePayload {
  type: AuthProfileType
  scheme: AuthScheme
  header_name?: string
  token_prefix?: string
  login_path?: string
  login_username_field?: string
  login_password_field?: string
  token_path?: string
  identities: AuthIdentityPayload[]
}

export interface AssessmentCreatePayload {
  base_url: string
  openapi_spec_url?: string
  target_name?: string
  allow_identity_registration: boolean
  authorized_for_active_testing: boolean
  classify: boolean
  request_budget: number
  auth_profile?: AuthProfilePayload
}

export interface TargetSummary {
  id: number
  name: string
  base_url: string
}

export interface StageOutcome {
  status?: string
  reason?: string
  [key: string]: unknown
}

export interface AssessmentSummary {
  complete: boolean
  status: string
  stages_persisted: boolean
  stage_source: string
  stages: Record<string, StageOutcome>
  failed_stages: string[]
  incomplete_reasons: string[]
  checks: Record<string, Record<string, unknown>>
}

export interface AssessmentStartResponse {
  scan_id: number
  target_id: number
  status: string
  started_at?: string | null
  completed_at?: string | null
  target?: TargetSummary | null
  base_url?: string
  origin?: string
  spec_source?: string | null
  findings_count?: number
  stages?: Record<string, StageOutcome>
  assessment?: AssessmentSummary
  message?: string
}

export interface ScanStatusResponse {
  id: number
  target_id: number
  status: string
  started_at: string | null
  completed_at: string | null
}

export interface FindingListItem {
  id: number
  scan_id: number
  endpoint_id: number
  finding_type: string
  severity: string
  status: string
  confidence: number | null
  method?: string | null
  path?: string | null
  operation_id?: string | null
  evidence_execution_ids: number[]
  description?: string
  title?: string | null
  category_label?: string | null
  what_happened?: string | null
  why_it_matters?: string | null
  impact?: string | null
  remediation?: string | null
  severity_reasoning?: string | null
}

export interface EvidenceItem {
  execution_id: number
  response_status: number | null
  request_headers: Record<string, unknown>
  request_body: Record<string, unknown> | null
  response_headers: Record<string, unknown>
  response_body: Record<string, unknown> | null
  executed_at: string | null
}

export interface ReportFinding {
  id: number
  finding_type: string
  severity: string
  status: string
  confidence: number | null
  description: string
  title?: string | null
  category_label?: string | null
  what_happened?: string | null
  why_it_matters?: string | null
  impact?: string | null
  remediation?: string | null
  severity_reasoning?: string | null
  endpoint: {
    id: number
    method: string | null
    path: string | null
    operation_id: string | null
  }
  evidence: EvidenceItem[]
}

export interface CoverageIssue {
  method?: string | null
  path?: string | null
  operation_id?: string | null
  parameter?: string | null
  location?: string | null
  reason?: string
}

export interface InventoryCoverage {
  spec_format?: string | null
  spec_version?: string | null
  base_path?: string | null
  operations_discovered?: number
  operations_normalized?: number
  operations_persisted?: number
  operations_inserted?: number
  operations_skipped_duplicate?: number
  operations_unsupported?: number
  operations_excluded_unsafe?: number
  operations_execution_restricted?: number
  operations_with_required_parameters?: number
  operations_with_unresolved_required_parameters?: number
  operations_requiring_request_body?: number
  limitations?: string[]
  unsupported_operations?: CoverageIssue[]
  excluded_operations?: CoverageIssue[]
  unresolved_parameters?: CoverageIssue[]
  required_request_bodies?: CoverageIssue[]
  execution_restrictions?: CoverageIssue[]
  details_truncated?: boolean
  [key: string]: unknown
}

export interface EndpointCheckResult {
  endpoint_id?: number
  method?: string | null
  path?: string | null
  operation_id?: string | null
  outcome?: string | null
  check_type?: string | null
  inspected?: boolean
  rationale?: string | null
  finding_id?: number | null
  [key: string]: unknown
}

export interface ReportSummary {
  headline: string
  verdict: string
  coverage: string
  confirmed_findings: number
  candidate_findings: number
  limitations: string[]
}

export interface ReportResponse {
  scan_id: number
  target_id: number
  target?: TargetSummary | null
  spec_source?: string | null
  status: string
  started_at: string | null
  completed_at: string | null
  total_endpoints: number
  classified_endpoints: number
  classification_rate: string
  findings_count: number
  findings_by_severity: Record<string, number>
  findings_by_status: Record<string, number>
  findings_by_type: Record<string, number>
  findings: ReportFinding[]
  summary?: ReportSummary | null
  resource_graph_summary: Record<string, unknown> | null
  inventory_coverage: InventoryCoverage | null
  findings_populated: boolean
  has_classified_endpoints: boolean
  zero_or_incomplete: Record<string, boolean | string>
  assessment: AssessmentSummary
}

export interface RecentAssessment {
  scan_id: number
  target_id: number
  base_url: string
  target_name: string
  status: string
  mode: AssessmentMode
  started_at: string
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}
