import type {
  AssessmentCreatePayload,
  AssessmentFormState,
  AssessmentStartResponse,
  AuthIdentityPayload,
  AuthProfilePayload,
  FindingListItem,
  ReportResponse,
  ScanStatusResponse,
} from '../types'
import { ApiError } from '../types'

export const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000'
export const ASSESSMENT_REQUEST_TIMEOUT_MS = 5 * 60 * 1000

export function getApiBaseUrl() {
  const configuredValue = import.meta.env.VITE_API_BASE_URL ?? DEFAULT_API_BASE_URL
  if (typeof configuredValue !== 'string' || !configuredValue.trim()) {
    throw new Error('VITE_API_BASE_URL is missing or empty.')
  }
  return configuredValue.replace(/\/$/, '')
}

function normalizePath(path: string) {
  const base = getApiBaseUrl()
  const joined = `${base}${path.startsWith('/') ? '' : '/'}${path}`
  return joined.replace(/([^:]\/)\/{2,}/g, '$1')
}

function formatDetail(payload: unknown, fallback: string) {
  if (!payload || typeof payload !== 'object') return fallback
  const detail = (payload as { detail?: unknown }).detail
  if (typeof detail === 'string' && detail.trim()) return detail
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === 'string') return item
        if (item && typeof item === 'object' && 'msg' in item) {
          const location = Array.isArray((item as { loc?: unknown }).loc)
            ? (item as { loc: unknown[] }).loc.filter((part) => part !== 'body').join('.')
            : ''
          const message = String((item as { msg?: unknown }).msg ?? '')
          return location ? `${location}: ${message}` : message
        }
        return ''
      })
      .filter(Boolean)
    if (messages.length) return messages.join(' ')
  }
  return fallback
}

function statusFallback(status: number) {
  if (status === 400) return 'The request was rejected as invalid.'
  if (status === 401 || status === 403) return 'This action is not authorized.'
  if (status === 404) return 'The requested assessment was not found.'
  if (status === 409) return 'The request conflicts with the current assessment state.'
  if (status === 422) return 'The request failed validation.'
  if (status === 429) return 'The API is rate-limiting requests. Try again shortly.'
  if (status === 503) return 'The assessment service is unavailable.'
  if (status >= 500) return 'The assessment service encountered an error.'
  return `Request failed (${status}).`
}

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(normalizePath(path), {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers ?? {}),
      },
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw error
    }
    if (error instanceof DOMException && error.name === 'TimeoutError') {
      throw new Error(
        'The assessment request exceeded the 5-minute wait limit. The backend may still be processing it; check the backend before retrying active tests.',
      )
    }
    throw new Error(
      'The browser could not complete a network request to the API. Check that the backend is running, VITE_API_BASE_URL is correct, and CORS allows this frontend origin.',
    )
  }

  if (!response.ok) {
    let message = statusFallback(response.status)
    try {
      const payload = await response.json()
      message = formatDetail(payload, message)
    } catch {
      const text = await response.text().catch(() => '')
      if (text.trim()) message = text.slice(0, 400)
    }
    throw new ApiError(message, response.status)
  }

  if (response.status === 204) {
    return undefined as T
  }

  try {
    return (await response.json()) as T
  } catch {
    throw new Error('The API returned a response that could not be parsed.')
  }
}

export function buildAssessmentPayload(form: AssessmentFormState): AssessmentCreatePayload {
  const payload: AssessmentCreatePayload = {
    base_url: form.base_url.trim(),
    allow_identity_registration: form.allow_identity_registration,
    authorized_for_active_testing: form.authorized_for_active_testing || form.authorization_confirmed,
    classify: form.classify,
    request_budget: form.request_budget,
  }

  const specUrl = form.openapi_spec_url.trim()
  if (form.mode === 'openapi' || specUrl) {
    payload.openapi_spec_url = specUrl || undefined
  }

  const targetName = form.target_name.trim()
  if (targetName) payload.target_name = targetName

  if (form.auth_profile.enabled) {
    payload.auth_profile = buildAuthProfilePayload(form)
  }

  return payload
}

function buildAuthProfilePayload(form: AssessmentFormState): AuthProfilePayload {
  const profile = form.auth_profile
  const identities: AuthIdentityPayload[] =
    profile.type === 'none'
      ? []
      : profile.identities.map((identity) => {
          const item: AuthIdentityPayload = { label: identity.label.trim() }
          if (identity.username.trim()) item.username = identity.username.trim()
          if (identity.password) item.password = identity.password
          if (identity.token) item.token = identity.token
          if (identity.api_key) item.api_key = identity.api_key
          if (identity.subject.trim()) item.subject = identity.subject.trim()
          if (identity.admin) item.admin = true
          return item
        })

  const payload: AuthProfilePayload = {
    type: profile.type,
    scheme: profile.scheme,
    identities,
  }

  if (profile.header_name.trim()) payload.header_name = profile.header_name.trim()
  if (profile.token_prefix) payload.token_prefix = profile.token_prefix
  if (profile.type === 'login') {
    payload.login_path = profile.login_path.trim()
    payload.login_username_field = profile.login_username_field.trim() || 'username'
    payload.login_password_field = profile.login_password_field.trim() || 'password'
    payload.token_path = profile.token_path.trim() || 'auth_token'
  }

  return payload
}

export async function createAssessment(
  form: AssessmentFormState,
  init?: RequestInit,
): Promise<AssessmentStartResponse> {
  const signal = init?.signal ?? AbortSignal.timeout(ASSESSMENT_REQUEST_TIMEOUT_MS)
  return apiFetch<AssessmentStartResponse>('/assessments', {
    method: 'POST',
    body: JSON.stringify(buildAssessmentPayload(form)),
    ...init,
    signal,
  })
}

export async function fetchScan(scanId: number, init?: RequestInit): Promise<ScanStatusResponse> {
  return apiFetch<ScanStatusResponse>(`/scans/${scanId}`, init)
}

export async function fetchFindings(scanId: number, init?: RequestInit): Promise<FindingListItem[]> {
  return apiFetch<FindingListItem[]>(`/scans/${scanId}/findings`, init)
}

export async function fetchReport(scanId: number, init?: RequestInit): Promise<ReportResponse> {
  return apiFetch<ReportResponse>(`/scans/${scanId}/report`, init)
}

export async function fetchHealth(init?: RequestInit): Promise<{ status: string; database: string }> {
  return apiFetch<{ status: string; database: string }>('/health', init)
}
