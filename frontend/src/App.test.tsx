import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import App from './App'
import { buildAssessmentPayload } from './lib/api'
import { DEFAULT_FORM } from './lib/storage'
import { completedReport, failedScan, incompleteReport, partialReport, zeroFindingReport } from './test/fixtures'

function jsonResponse(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  )
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  )
}

describe('APIVigilante application', () => {
  beforeEach(() => {
    window.localStorage.clear()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('renders the brand, navigation, and start CTA', () => {
    renderAt('/')
    expect(screen.getByRole('link', { name: /APIVigilante home/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Overview' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'New assessment' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Recent' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /start assessment/i })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /see what your api exposes/i })).toBeInTheDocument()
  })

  it('navigates between overview, new assessment, and recent', async () => {
    const user = userEvent.setup()
    renderAt('/')
    await user.click(screen.getByRole('link', { name: 'New assessment' }))
    expect(await screen.findByRole('heading', { name: /configure an authorized target/i })).toBeInTheDocument()
    await user.click(screen.getByRole('link', { name: 'Recent' }))
    expect(await screen.findByRole('heading', { name: /recent assessments/i })).toBeInTheDocument()
    expect(screen.getByText(/there is no/i)).toHaveTextContent('GET /scans')
  })

  it('validates the form before submitting', async () => {
    const user = userEvent.setup()
    renderAt('/new-assessment')
    await user.click(screen.getByRole('button', { name: /start assessment/i }))
    expect(await screen.findByText(/api base url is required/i)).toBeInTheDocument()
    expect(screen.getByText(/confirm that you are authorized/i)).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('does not require an OpenAPI URL in OpenAPI-assisted mode', async () => {
    const user = userEvent.setup()
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: 'The target URL is invalid or not allowed.' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderAt('/new-assessment')
    await user.click(screen.getByRole('radio', { name: /openapi-assisted/i }))
    await user.type(screen.getByLabelText(/api base url/i), 'http://127.0.0.1:5001')
    await user.click(screen.getByLabelText(/i confirm this target is authorized/i))
    await user.click(screen.getByRole('button', { name: /start assessment/i }))

    // The specification is optional: the request is attempted without it and
    // the backend falls back to bounded discovery.
    expect(await screen.findByRole('alert')).toHaveTextContent(/target url is invalid/i)
    expect(screen.queryByText(/openapi specification url is required/i)).not.toBeInTheDocument()
    const posted = vi.mocked(fetch).mock.calls.find(([request]) => String(request).endsWith('/assessments'))
    expect(posted).toBeTruthy()
    const body = JSON.parse(String(posted?.[1]?.body))
    expect(body.openapi_spec_url).toBeUndefined()
  })

  it('sends discovery-first payloads without openapi_spec_url', () => {
    const payload = buildAssessmentPayload({
      ...DEFAULT_FORM,
      mode: 'discovery',
      base_url: 'http://127.0.0.1:5001',
      openapi_spec_url: '',
      authorization_confirmed: true,
      authorized_for_active_testing: true,
    })
    expect(payload.openapi_spec_url).toBeUndefined()
    expect(payload.base_url).toBe('http://127.0.0.1:5001')
    expect(payload.authorized_for_active_testing).toBe(true)
  })

  it('sends OpenAPI-assisted payloads with the specification URL', () => {
    const payload = buildAssessmentPayload({
      ...DEFAULT_FORM,
      mode: 'openapi',
      base_url: 'http://127.0.0.1:5001',
      openapi_spec_url: 'http://127.0.0.1:5001/openapi.json',
      authorization_confirmed: true,
    })
    expect(payload.openapi_spec_url).toBe('http://127.0.0.1:5001/openapi.json')
  })

  it('creates an assessment and opens the returned scan', async () => {
    const user = userEvent.setup()
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/assessments')) {
        return jsonResponse({ scan_id: 12, target_id: 3, status: 'completed', base_url: 'http://127.0.0.1:5001' }, 201)
      }
      if (url.endsWith('/scans/12')) {
        return jsonResponse({ id: 12, target_id: 3, status: 'completed', started_at: '2026-10-25T12:00:00Z', completed_at: '2026-10-25T12:01:00Z' })
      }
      if (url.endsWith('/scans/12/report')) return jsonResponse(completedReport)
      return jsonResponse({ detail: 'missing mock' }, 404)
    })

    renderAt('/new-assessment')
    await user.type(screen.getByLabelText(/api base url/i), 'http://127.0.0.1:5001')
    await user.click(screen.getByLabelText(/i confirm this target is authorized/i))
    await user.click(screen.getByRole('button', { name: /start assessment/i }))

    expect(await screen.findByRole('heading', { name: /local test api/i })).toBeInTheDocument()
    const posted = vi.mocked(fetch).mock.calls.find(([request]) => String(request).endsWith('/assessments'))
    expect(posted).toBeTruthy()
    const body = JSON.parse(String(posted?.[1]?.body))
    expect(body.openapi_spec_url).toBeUndefined()
    expect(body.base_url).toBe('http://127.0.0.1:5001')
    expect(screen.getByText(/cross-identity access succeeded/i)).toBeInTheDocument()
  })

  it('shows backend submission errors', async () => {
    const user = userEvent.setup()
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: 'The target URL is invalid or not allowed.' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderAt('/new-assessment')
    await user.type(screen.getByLabelText(/api base url/i), 'http://127.0.0.1:5001')
    await user.click(screen.getByLabelText(/i confirm this target is authorized/i))
    await user.click(screen.getByRole('button', { name: /start assessment/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/target url is invalid/i)
  })

  it('shows database service errors as backend responses', async () => {
    const user = userEvent.setup()
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: 'Database unavailable. Verify PostgreSQL is running.' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderAt('/new-assessment')
    await user.type(screen.getByLabelText(/api base url/i), 'http://127.0.0.1:5001')
    await user.click(screen.getByLabelText(/i confirm this target is authorized/i))
    await user.click(screen.getByRole('button', { name: /start assessment/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/database unavailable/i)
    expect(screen.getByRole('alert')).not.toHaveTextContent(/CORS/i)
  })

  it('renders findings, evidence, and report details from the backend', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/scans/12')) {
        return jsonResponse({ id: 12, target_id: 3, status: 'completed', started_at: null, completed_at: null })
      }
      if (url.endsWith('/scans/12/report')) return jsonResponse(completedReport)
      return jsonResponse({ detail: 'not found' }, 404)
    })
    renderAt('/assessment/12')
    expect((await screen.findAllByText('/users/{user_id}')).length).toBeGreaterThan(0)
    expect(screen.getByText(/High severity/i)).toBeInTheDocument()
  })

  it('renders a truthful zero-finding state', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/scans/12')) {
        return jsonResponse({ id: 12, target_id: 3, status: 'completed', started_at: null, completed_at: null })
      }
      if (url.endsWith('/scans/12/report')) return jsonResponse(zeroFindingReport)
      return jsonResponse({ detail: 'not found' }, 404)
    })
    renderAt('/assessment/12')
    expect(await screen.findByText(/no findings were persisted/i)).toBeInTheDocument()
    expect(screen.getByText(/not an all-clear score/i)).toBeInTheDocument()
  })

  it('renders incomplete and failed assessment states', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/scans/12')) return jsonResponse(failedScan)
      if (url.endsWith('/scans/12/report')) return jsonResponse(incompleteReport)
      return jsonResponse({ detail: 'not found' }, 404)
    })
    renderAt('/assessment/12')
    expect(await screen.findByText(/scan is marked failed/i)).toBeInTheDocument()
    expect(screen.getByText(/identity registration was not approved/i)).toBeInTheDocument()
  })

  it('renders the report and export actions', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/scans/12/report')) return jsonResponse(completedReport)
      return jsonResponse({ detail: 'not found' }, 404)
    })
    renderAt('/assessment/12/report')
    expect(await screen.findByRole('heading', { name: /scan 12/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /download json/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /download markdown/i })).toBeInTheDocument()
    expect(screen.getByText(/cross-identity access succeeded/i)).toBeInTheDocument()
  })

  it('renders a partial assessment with summary and human-readable findings', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/scans/12')) {
        return jsonResponse({ id: 12, target_id: 3, status: 'partial', started_at: null, completed_at: null })
      }
      if (url.endsWith('/scans/12/report')) return jsonResponse(partialReport)
      return jsonResponse({ detail: 'not found' }, 404)
    })
    renderAt('/assessment/12')
    expect(await screen.findByText(/assessment completed with limitations/i)).toBeInTheDocument()
    expect(screen.getByText(/incomplete assessment/i)).toBeInTheDocument()
    expect(screen.getByText(/broken object-level authorization on GET/i)).toBeInTheDocument()
    expect(screen.getAllByText(/view evidence and remediation/i).length).toBeGreaterThan(0)
  })

  it('shows plain-language detail and remediation on the finding page', async () => {
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/scans/12/report')) return jsonResponse(partialReport)
      return jsonResponse({ detail: 'not found' }, 404)
    })
    renderAt('/assessment/12/finding/45')
    expect(await screen.findByRole('heading', { name: /possible sensitive data exposure/i })).toBeInTheDocument()
    expect(screen.getByText(/the response contained fields that may be sensitive/i)).toBeInTheDocument()
    expect(screen.getByText(/return only required fields/i)).toBeInTheDocument()
    expect(screen.getByText(/rated medium because evidence is indirect/i)).toBeInTheDocument()
  })

  it('explains that a report is not ready while the scan is running', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ detail: 'The assessment is still running.' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderAt('/assessment/12/report')
    expect(await screen.findByText(/report not ready yet/i)).toBeInTheDocument()
  })

  it('handles a missing report', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ detail: 'Scan not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderAt('/assessment/99/report')
    expect(await screen.findByText(/report not found/i)).toBeInTheDocument()
    expect(screen.getByText(/scan not found/i)).toBeInTheDocument()
  })

  it('handles network failures without crashing', async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError('Failed to fetch'))
    renderAt('/assessment/12')
    expect(await screen.findByRole('alert')).toHaveTextContent(/network request/i)
    expect(screen.getByRole('alert')).toHaveTextContent(/CORS/i)
  })

  it('clears the submit state and explains assessment request timeouts', async () => {
    const user = userEvent.setup()
    vi.mocked(fetch).mockRejectedValueOnce(new DOMException('timed out', 'TimeoutError'))
    renderAt('/new-assessment')
    await user.type(screen.getByLabelText(/api base url/i), 'http://127.0.0.1:5001')
    await user.click(screen.getByLabelText(/i confirm this target is authorized/i))
    await user.click(screen.getByRole('button', { name: /start assessment/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/5-minute wait limit/i)
    expect(screen.getByRole('button', { name: /start assessment/i })).toBeEnabled()
  })

  it('opens finding evidence from the report payload', async () => {
    const user = userEvent.setup()
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/scans/12')) {
        return jsonResponse({ id: 12, target_id: 3, status: 'completed', started_at: null, completed_at: null })
      }
      if (url.endsWith('/scans/12/report')) return jsonResponse(completedReport)
      return jsonResponse({ detail: 'not found' }, 404)
    })
    renderAt('/assessment/12')
    await user.click(await screen.findByRole('link', { name: /view evidence/i }))
    expect(await screen.findByText(/execution 70/i)).toBeInTheDocument()
    expect(screen.getByText(/\*\*\*REDACTED\*\*\*/)).toBeInTheDocument()
  })

  it('keeps primary navigation usable in a narrow viewport', async () => {
    window.innerWidth = 390
    const user = userEvent.setup()
    renderAt('/')
    await user.click(screen.getByRole('button', { name: /menu/i }))
    const nav = screen.getByRole('navigation', { name: /primary/i })
    expect(nav).toHaveClass('open')
    expect(within(nav).getByRole('link', { name: 'New assessment' })).toBeInTheDocument()
  })

  it('prevents duplicate submits while a request is in flight', async () => {
    const user = userEvent.setup()
    let finish: (value: Response) => void = () => undefined
    vi.mocked(fetch).mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve
        }),
    )
    renderAt('/new-assessment')
    await user.type(screen.getByLabelText(/api base url/i), 'http://127.0.0.1:5001')
    await user.click(screen.getByLabelText(/i confirm this target is authorized/i))
    const submit = screen.getByRole('button', { name: /start assessment/i })
    await user.click(submit)
    expect(submit).toBeDisabled()
    finish(
      new Response(JSON.stringify({ scan_id: 1, target_id: 1, status: 'completed' }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1))
  })
})
