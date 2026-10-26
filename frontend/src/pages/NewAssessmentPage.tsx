import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { createAssessment } from '../lib/api'
import { emptyIdentity, persistForm } from '../lib/storage'
import { rememberAssessment } from '../lib/storage'
import type { AssessmentFormState, AuthIdentityForm } from '../types'
import { ErrorBanner } from '../components/States'

function validate(form: AssessmentFormState) {
  const errors: Record<string, string> = {}
  if (!form.base_url.trim()) errors.base_url = 'API base URL is required.'
  else if (!/^https?:\/\//i.test(form.base_url.trim())) errors.base_url = 'Enter an http or https URL.'

  if (form.openapi_spec_url.trim() && !/^https?:\/\//i.test(form.openapi_spec_url.trim())) {
    errors.openapi_spec_url = 'If provided, the specification URL must use http or https.'
  }

  if (!Number.isInteger(form.request_budget) || form.request_budget < 1 || form.request_budget > 100) {
    errors.request_budget = 'Request budget must be an integer between 1 and 100.'
  }

  if (!form.authorization_confirmed) {
    errors.authorization_confirmed = 'Confirm that you are authorized to assess this target.'
  }

  if (form.auth_profile.enabled) {
    if (form.auth_profile.type === 'login' && !form.auth_profile.login_path.trim()) {
      errors.auth_profile = 'A login profile requires a relative login path such as /auth/login.'
    }
    if (form.auth_profile.type !== 'none' && form.auth_profile.identities.length === 0) {
      errors.auth_profile = `A ${form.auth_profile.type} profile requires at least one identity.`
    }
    for (const identity of form.auth_profile.identities) {
      if (!identity.label.trim()) errors.auth_profile = 'Each identity needs a non-secret label.'
    }
  }

  return errors
}

export function NewAssessmentPage({
  form,
  setForm,
}: {
  form: AssessmentFormState
  setForm: (value: AssessmentFormState) => void
}) {
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState('')
  const navigate = useNavigate()

  const update = <Key extends keyof AssessmentFormState>(key: Key, value: AssessmentFormState[Key]) => {
    const next = { ...form, [key]: value }
    setForm(next)
    persistForm(next)
  }

  const updateProfile = (patch: Partial<AssessmentFormState['auth_profile']>) => {
    update('auth_profile', { ...form.auth_profile, ...patch })
  }

  const updateIdentity = (id: string, patch: Partial<AuthIdentityForm>) => {
    updateProfile({
      identities: form.auth_profile.identities.map((identity) =>
        identity.id === id ? { ...identity, ...patch } : identity,
      ),
    })
  }

  const disableSubmit = submitting

  const modeHint = useMemo(
    () =>
      form.mode === 'openapi'
        ? 'Recommended when you have a contract: the specification URL is sent as openapi_spec_url and must share the target origin. If it is missing or unreachable, the backend falls back to bounded discovery.'
        : 'Only a target URL is required. The backend probes common OpenAPI paths, then performs bounded same-origin HTML-link discovery if no specification is available. Unlinked API routes may remain undiscovered.',
    [form.mode],
  )

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const nextErrors = validate(form)
    setErrors(nextErrors)
    if (Object.keys(nextErrors).length) {
      setSubmitError('Fix the highlighted fields before starting.')
      return
    }

    try {
      setSubmitting(true)
      setSubmitError('')
      const assessment = await createAssessment({
        ...form,
        authorized_for_active_testing: form.authorization_confirmed,
      })
      rememberAssessment({
        scan_id: assessment.scan_id,
        target_id: assessment.target_id,
        base_url: assessment.base_url || form.base_url,
        target_name: assessment.target?.name || form.target_name || form.base_url,
        status: assessment.status,
        mode: form.mode,
        started_at: new Date().toISOString(),
      })
      navigate(`/assessment/${assessment.scan_id}`)
    } catch (error) {
      setSubmitError(error instanceof Error ? error.message : 'The assessment could not be started.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <header className="page-header">
        <div>
          <p className="kicker">New assessment</p>
          <h1>Configure an authorized target</h1>
        </div>
      </header>

      <form className="form-card" onSubmit={handleSubmit} noValidate>
        <fieldset className="field full" style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="field-label">Assessment mode</legend>
          <div className="mode-grid" role="radiogroup" aria-label="Assessment mode">
            <label className="mode-option">
              <input
                type="radio"
                name="mode"
                value="discovery"
                checked={form.mode === 'discovery'}
                onChange={() => update('mode', 'discovery')}
              />
              <strong>Discovery-first</strong>
              <span>Only a target URL is required. The backend probes known OpenAPI paths, then follows a bounded set of same-origin HTML links.</span>
            </label>
            <label className="mode-option">
              <input
                type="radio"
                name="mode"
                value="openapi"
                checked={form.mode === 'openapi'}
                onChange={() => update('mode', 'openapi')}
              />
              <strong>OpenAPI-assisted</strong>
              <span>Recommended when a contract exists. The specification URL remains optional and falls back to discovery when unavailable.</span>
            </label>
          </div>
          <p className="help">{modeHint}</p>
        </fieldset>

        <div className="field-grid">
          <label className="field">
            <span>
              API base URL <span className="req">*</span>
            </span>
            <input
              type="url"
              value={form.base_url}
              onChange={(event) => update('base_url', event.target.value)}
              placeholder="http://127.0.0.1:5001"
              aria-invalid={Boolean(errors.base_url)}
            />
            {errors.base_url ? <small className="field-error">{errors.base_url}</small> : (
              <small className="help">Must pass the backend SSRF and origin policy.</small>
            )}
          </label>

          <label className="field">
            <span>
              OpenAPI specification URL <span className="optional">optional</span>
            </span>
            <input
              type="url"
              value={form.openapi_spec_url}
              onChange={(event) => update('openapi_spec_url', event.target.value)}
              placeholder="http://127.0.0.1:5001/metadata/openapi.json"
              aria-invalid={Boolean(errors.openapi_spec_url)}
            />
            {errors.openapi_spec_url ? (
              <small className="field-error">{errors.openapi_spec_url}</small>
            ) : (
              <small className="help">Optional. When omitted or unreachable, the backend uses bounded discovery. Must share the target origin.</small>
            )}
          </label>

          <label className="field">
            <span>
              Target name <span className="optional">optional</span>
            </span>
            <input
              type="text"
              value={form.target_name}
              onChange={(event) => update('target_name', event.target.value)}
              placeholder="Local test API"
            />
          </label>

          <label className="field">
            <span>Request budget</span>
            <input
              type="number"
              min={1}
              max={100}
              value={form.request_budget}
              onChange={(event) => update('request_budget', Number(event.target.value))}
              aria-invalid={Boolean(errors.request_budget)}
            />
            {errors.request_budget ? (
              <small className="field-error">{errors.request_budget}</small>
            ) : (
              <small className="help">Maximum target requests for BOLA/BFLA; sensitive-data checks share this budget.</small>
            )}
          </label>
        </div>

        <div className="check-stack">
          <label className="check-row">
            <input
              type="checkbox"
              checked={form.classify}
              onChange={(event) => update('classify', event.target.checked)}
            />
            <span>Run optional LLM classification when a provider is configured.</span>
          </label>
          <label className="check-row">
            <input
              type="checkbox"
              checked={form.allow_identity_registration}
              onChange={(event) => update('allow_identity_registration', event.target.checked)}
            />
            <span>
              Allow identity registration for active testing. Required for BOLA, BFLA, and sensitive-data requests.
            </span>
          </label>
          <label className="check-row">
            <input
              type="checkbox"
              checked={form.authorization_confirmed}
              onChange={(event) => update('authorization_confirmed', event.target.checked)}
            />
            <span>
              I confirm this target is authorized for assessment. This is sent as{' '}
              <code>authorized_for_active_testing</code>.
            </span>
          </label>
          {errors.authorization_confirmed ? (
            <small className="field-error">{errors.authorization_confirmed}</small>
          ) : null}
        </div>

        <div className="notice warning">
          Assessments must target systems you are authorized to test. Allowlisting, SSRF defenses, and active-test
          gates are enforced by the backend, not this form.
        </div>

        <details>
          <summary>Optional authentication profile</summary>
          <p className="help" style={{ margin: '12px 0' }}>
            Use this only for targets that do not follow the built-in registration contract. Secrets are submitted once
            and are not stored in the browser.
          </p>
          <label className="check-row">
            <input
              type="checkbox"
              checked={form.auth_profile.enabled}
              onChange={(event) => updateProfile({ enabled: event.target.checked })}
            />
            <span>Include an <code>auth_profile</code> object in the request.</span>
          </label>
          {form.auth_profile.enabled ? (
            <div className="field-grid" style={{ marginTop: 16 }}>
              <label className="field">
                <span>Profile type</span>
                <select
                  value={form.auth_profile.type}
                  onChange={(event) =>
                    updateProfile({ type: event.target.value as AssessmentFormState['auth_profile']['type'] })
                  }
                >
                  <option value="static">static</option>
                  <option value="login">login</option>
                  <option value="none">none</option>
                </select>
              </label>
              <label className="field">
                <span>Scheme</span>
                <select
                  value={form.auth_profile.scheme}
                  onChange={(event) =>
                    updateProfile({ scheme: event.target.value as AssessmentFormState['auth_profile']['scheme'] })
                  }
                >
                  <option value="bearer">bearer</option>
                  <option value="api_key">api_key</option>
                  <option value="basic">basic</option>
                  <option value="custom">custom</option>
                </select>
              </label>
              <label className="field">
                <span>Header name</span>
                <input
                  value={form.auth_profile.header_name}
                  onChange={(event) => updateProfile({ header_name: event.target.value })}
                  placeholder="Authorization"
                />
              </label>
              {form.auth_profile.type === 'login' ? (
                <>
                  <label className="field">
                    <span>Login path</span>
                    <input
                      value={form.auth_profile.login_path}
                      onChange={(event) => updateProfile({ login_path: event.target.value })}
                      placeholder="/auth/login"
                    />
                  </label>
                  <label className="field">
                    <span>Token path</span>
                    <input
                      value={form.auth_profile.token_path}
                      onChange={(event) => updateProfile({ token_path: event.target.value })}
                    />
                  </label>
                </>
              ) : null}
              {errors.auth_profile ? <small className="field-error full">{errors.auth_profile}</small> : null}
              <div className="field full">
                <div className="actions">
                  <button
                    className="button secondary"
                    type="button"
                    onClick={() =>
                      updateProfile({
                        identities: [...form.auth_profile.identities, emptyIdentity(form.auth_profile.identities.length + 1)],
                      })
                    }
                  >
                    Add identity
                  </button>
                </div>
                {form.auth_profile.identities.map((identity) => (
                  <div className="identity-card" key={identity.id}>
                    <label className="field">
                      <span>Label</span>
                      <input value={identity.label} onChange={(event) => updateIdentity(identity.id, { label: event.target.value })} />
                    </label>
                    <div className="field-grid">
                      <label className="field">
                        <span>Username</span>
                        <input value={identity.username} onChange={(event) => updateIdentity(identity.id, { username: event.target.value })} />
                      </label>
                      <label className="field">
                        <span>Password</span>
                        <input type="password" value={identity.password} onChange={(event) => updateIdentity(identity.id, { password: event.target.value })} autoComplete="off" />
                      </label>
                      <label className="field">
                        <span>Token</span>
                        <input type="password" value={identity.token} onChange={(event) => updateIdentity(identity.id, { token: event.target.value })} autoComplete="off" />
                      </label>
                      <label className="field">
                        <span>API key</span>
                        <input type="password" value={identity.api_key} onChange={(event) => updateIdentity(identity.id, { api_key: event.target.value })} autoComplete="off" />
                      </label>
                    </div>
                    <label className="check-row">
                      <input type="checkbox" checked={identity.admin} onChange={(event) => updateIdentity(identity.id, { admin: event.target.checked })} />
                      <span>Admin identity</span>
                    </label>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </details>

        {submitError ? <ErrorBanner message={submitError} /> : null}

        <div className="actions">
          <button className="button primary" type="submit" disabled={disableSubmit}>
            {submitting ? 'Starting assessment…' : 'Start assessment'}
          </button>
          <Link className="button secondary" to="/">
            Cancel
          </Link>
        </div>
        <p className="help">
          The backend validates the target, returns a scan identifier immediately, and runs the checks in the
          background. You will be taken to live progress and can leave this page safely.
        </p>
      </form>
    </div>
  )
}
