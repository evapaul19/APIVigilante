import type { AssessmentFormState, AssessmentMode, RecentAssessment } from '../types'

const FORM_KEY = 'apivigilante.form.v2'
const RECENT_KEY = 'apivigilante.recent.v1'

export const DEFAULT_AUTH_PROFILE = {
  enabled: false,
  type: 'static' as const,
  scheme: 'bearer' as const,
  header_name: '',
  token_prefix: 'Bearer ',
  login_path: '',
  login_username_field: 'username',
  login_password_field: 'password',
  token_path: 'auth_token',
  identities: [],
}

export const DEFAULT_FORM: AssessmentFormState = {
  mode: 'discovery',
  base_url: '',
  openapi_spec_url: '',
  target_name: '',
  allow_identity_registration: false,
  authorized_for_active_testing: false,
  classify: true,
  request_budget: 40,
  authorization_confirmed: false,
  auth_profile: DEFAULT_AUTH_PROFILE,
}

function readJson<T>(key: string): T | null {
  try {
    const stored = window.localStorage.getItem(key)
    return stored ? (JSON.parse(stored) as T) : null
  } catch {
    return null
  }
}

export function loadPersistedForm(): AssessmentFormState {
  const stored = readJson<Partial<AssessmentFormState>>(FORM_KEY)
  if (!stored) return DEFAULT_FORM
  return {
    ...DEFAULT_FORM,
    ...stored,
    auth_profile: {
      ...DEFAULT_AUTH_PROFILE,
      enabled: false,
      identities: [],
    },
    authorization_confirmed: false,
    authorized_for_active_testing: false,
  }
}

export function persistForm(form: AssessmentFormState) {
  const { auth_profile: _secrets, authorization_confirmed: _auth, authorized_for_active_testing: _active, ...safe } =
    form
  void _secrets
  void _auth
  void _active
  window.localStorage.setItem(FORM_KEY, JSON.stringify(safe))
}

export function loadRecentAssessments(): RecentAssessment[] {
  const stored = readJson<RecentAssessment[]>(RECENT_KEY)
  return Array.isArray(stored) ? stored : []
}

export function rememberAssessment(entry: RecentAssessment) {
  const existing = loadRecentAssessments().filter((item) => item.scan_id !== entry.scan_id)
  window.localStorage.setItem(RECENT_KEY, JSON.stringify([entry, ...existing].slice(0, 25)))
}

export function emptyIdentity(index = 1) {
  return {
    id: `identity-${Date.now()}-${index}`,
    label: `identity_${index}`,
    username: '',
    password: '',
    token: '',
    api_key: '',
    subject: '',
    admin: false,
  }
}

export function modeFromForm(mode: AssessmentMode) {
  return mode === 'openapi' ? 'openapi' : 'discovery'
}
