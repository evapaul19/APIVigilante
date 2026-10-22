# APIVigilante: API Security Assessment System

APIVigilante is an OpenAPI-driven API security assessment prototype. It
discovers endpoints from a target's specification, builds a deterministic
resource graph, runs bounded authorization and sensitive-data checks against
explicitly authorized origins, and persists sanitized evidence and stage-aware
reports in PostgreSQL.

Implemented checks:

- OpenAPI/Swagger discovery and deterministic endpoint inventory.
- Optional LLM risk classification (Google Gemini or OpenRouter).
- BOLA checks for the documented email-update, password-update, and delete
  operations, plus read-only BOLA on object-level authenticated GET endpoints.
- BFLA checks for authenticated operations documented as administrator-only,
  currently the administrator-DELETE execution shape.
- Sensitive-data inspection of actual JSON responses, with confirmed findings
  and evidence-backed candidates.
- Redacted evidence persistence, findings, and stage-aware reports.
- Explicit target authorization, SSRF protections, bounded execution, shared
  request budgets, and an isolated local test API.

Active testing is never implicit. It requires
`allow_identity_registration=true` on `POST /assessments` and an origin that is
explicitly allowlisted. Other targets can be inventoried, but active checks are
reported as `not_supported`.

## Architecture

The supported application flow is `POST /assessments`:

1. Validate the target URL and optional OpenAPI spec URL.
2. Acquire the spec and save it locally.
3. Persist the endpoint inventory (recon).
4. Optionally classify endpoints with an LLM.
5. Build the resource graph from persisted endpoints.
6. Run BOLA/BFLA checks when active testing is approved.
7. Inspect GET responses for sensitive data within the remaining budget.
8. Persist the nine assessment-stage outcomes and return report links.

The main modules are under `src/api_security_system/`:

```text
api.py                 FastAPI routes, findings, and report assembly
auth/                  Registration/login helpers and AuthContext
authz_bola/            Candidate selection, BOLA/BFLA runners, verification
db/                    SQLModel models, enums, engine, redaction
llm/                   Provider abstraction
recon/                 OpenAPI parsing, inventory, optional classification
request_executor/      SSRF-safe HTTP execution and response limits
resource_graph/        Deterministic resource relationships
sensitive_data/        Response inspection and finding creation
targets/               URL/spec validation, authorization, orchestration
safe_gets.py           Shared GET side-effect classifier
```

`langgraph_workflow.py` is an optional, legacy scan-driven workflow wrapper.
It is not used by the supported `POST /assessments` path. It requires
`--allow-active` before it will run authorization checks.

## Prerequisites

- Docker Desktop with Compose.
- Python 3.12 or newer.
- The existing project virtual environment at `.venv`.
- PostgreSQL reachable through the configured `DATABASE_URL`.
- About 2 GB of available memory.

## 1. Configure Environment

Copy the template and edit `.env` locally. If `.env` already exists, edit it in
place; do not overwrite existing secrets.

```powershell
Copy-Item .env.example .env
```

At minimum, set database values matching the existing PostgreSQL volume:

```dotenv
DATABASE_URL=postgresql+psycopg://api_security:CHANGE_ME@localhost:5432/api_security
POSTGRES_PASSWORD=CHANGE_ME
```

Never commit `.env` or print its contents. `.gitignore` excludes `.env` and
other local environment files. The application loads `.env` from the project
root even when the process is started from another directory.

### Authorized target origins

Active checks are limited to explicitly allowlisted origins:

- `http://localhost:5000` (the bundled VAmPI contract).
- `http://127.0.0.1:5001` only when this opt-in is set:

```dotenv
APIVIGILANTE_ENABLE_TEST_TARGET=1
```

The second origin exists for the isolated vulnerable test API in
`vulnerable_test_api/`. It is exact-origin gated; do not enable it for a
different loopback service and do not expose that test API beyond loopback.

### Optional LLM classification

Set one key in `.env`:

```dotenv
GEMINI_API_KEY=your-key
# or
OPENROUTER_API_KEY=your-key
```

Optional controls:

- `LLM_PROVIDER=google|openrouter` forces a provider.
- `GEMINI_MODEL` and `OPENROUTER_MODEL` override model names.
- Without a key, use `classify=false`. Otherwise classification is attempted
  and reported as failed or partial while the deterministic inventory remains
  persisted.

### BFLA administrator identity

BFLA needs a higher-privileged identity that already exists on the target:

```dotenv
VAMPI_ADMIN_USERNAME=your-admin-user
VAMPI_ADMIN_PASSWORD=your-admin-password
```

There is no credential fallback. If either value is missing, or the identity
does not verify as an administrator, BFLA reports `unsupported`; it does not
guess credentials.

## 2. Start Infrastructure

The repository's Compose file starts PostgreSQL only:

```powershell
docker compose up -d
docker compose ps
docker compose exec postgres pg_isready -U api_security
```

The VAmPI container, if used, is managed separately. Do not remove or recreate
the PostgreSQL volume. If the volume already exists, its password must match
`POSTGRES_PASSWORD` and `DATABASE_URL`.

For a self-contained demonstration, start the isolated test API on loopback
from the project root:

```powershell
& .\.venv\Scripts\python.exe -m uvicorn vulnerable_test_api.app:app --host 127.0.0.1 --port 5001
```

That API is intentionally vulnerable and intended only for local verification.
Do not expose it to a network.

## 3. Apply Database Migrations

The schema is managed with Alembic. The current head is
`3f2a9c1d4b7e` (the `assessment_stages` table). Run from the project root so
the root `.env` is loaded:

```powershell
& .\.venv\Scripts\python.exe -m alembic current
& .\.venv\Scripts\python.exe -m alembic upgrade head
& .\.venv\Scripts\python.exe -m alembic current
```

Do not run `alembic downgrade`, reset volumes, or delete records as part of
normal startup. Existing historical scans are read using their persisted
stages and findings.

## 4. Start the API

Using the existing virtual environment:

```powershell
& .\.venv\Scripts\python.exe -m uvicorn api_security_system.api:app --host 127.0.0.1 --port 8000
```

Alternative entry point:

```powershell
& .\.venv\Scripts\api-security-system.exe
```

The API, Swagger UI, and health check are at:

- Swagger UI: `http://127.0.0.1:8000/docs`
- OpenAPI JSON: `http://127.0.0.1:8000/openapi.json`
- Health: `http://127.0.0.1:8000/health`

If port 8000 is already in use, stop the old process or choose a different
port. Startup requires a reachable PostgreSQL database and a `.env` with
`DATABASE_URL`.

## 5. Run an Assessment

`POST /assessments` is the main one-call flow. It creates the target and scan,
acquires the spec, runs recon, optionally classifies endpoints, builds the
resource graph, and runs supported active checks when explicitly approved.

Inventory-only baseline (no active requests, optional classification):

```powershell
$body = @{
  base_url = "http://127.0.0.1:5001"
  openapi_spec_url = "http://127.0.0.1:5001/openapi.json"
  target_name = "isolated-vulnerable-test-api"
  classify = $false
  allow_identity_registration = $false
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/assessments" `
  -ContentType "application/json" `
  -Body $body
```

Active assessment against the explicitly allowlisted isolated test API:

```powershell
$body = @{
  base_url = "http://127.0.0.1:5001"
  openapi_spec_url = "http://127.0.0.1:5001/openapi.json"
  target_name = "isolated-vulnerable-test-api"
  classify = $false
  allow_identity_registration = $true
  request_budget = 40
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/assessments" `
  -ContentType "application/json" `
  -Body $body
```

Notes:

- `request_budget` is 1-100.
- BOLA/BFLA and sensitive-data checks share that budget. Sensitive inspection
  receives only what BOLA/BFLA did not use and is additionally capped at 20.
- `openapi_spec_url` must share the target origin. When omitted, common
  discovery paths are tried.
- `classify=false` avoids an LLM call. It does not disable deterministic
  checks.

Retrieve the persisted report and findings:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/scans/{scan_id}/report"
Invoke-RestMethod "http://127.0.0.1:8000/scans/{scan_id}/findings"
```

The findings endpoint includes endpoint method/path and
`evidence_execution_ids`. The report includes sanitized request/response
evidence, so it is the authoritative place to review a finding.

## 6. Read the Report

The report uses persisted stage records as the authority for what actually ran.
Important fields include:

- `assessment.complete`: true only when the scan completed, endpoints exist,
  and no incomplete reason was recorded.
- `assessment.stages_persisted` and `assessment.stage_source`: distinguish new
  stage-aware scans from legacy scans using `legacy_fallback`.
- `assessment.incomplete_reasons`: explicit skipped, unsupported, partial, and
  failed outcomes.
- `assessment.checks.recon`, `classification`, `resource_graph`,
  `authorization_tests`, `bola`, `bfla`, `sensitive_data`, `persistence`, and
  `report`.
- `findings_by_status`: `candidate` means evidence is suggestive but not
  confirmed; `confirmed` means deterministic post-condition verification
  succeeded.
- `findings[].evidence`: redacted execution records linked to that finding.

Stage statuses are intentionally explicit: `passed`, `succeeded`, `completed`,
`built`, `performed`, `not_requested`, `not_run`, `not_applicable`,
`unsupported`, `not_supported`, `partial`, `stopped_early`, or `failed`.
Finding statuses are `candidate`, `confirmed`, or `false_positive`. Finding
types are `bola`, `bfla`, or `sensitive_data`.

Legacy scans without stage rows still return a report using
`stage_source: "legacy_fallback"`. Missing active-check evidence is not treated
as a clean result.

## API Routes

| Method | Route | Purpose |
|--------|-------|---------|
| GET | `/health` | Application and database health |
| POST | `/assessments` | One-call assessment and stage-aware response |
| POST | `/scans` | Create a pending scan for an existing target |
| GET | `/scans/{scan_id}` | Scan lifecycle status |
| GET | `/scans/{scan_id}/findings` | Persisted findings with endpoint/evidence references |
| GET | `/scans/{scan_id}/report` | Full report with stage outcomes and evidence |
| POST | `/scans/{scan_id}/recon` | Manual recon for an existing scan |
| POST | `/scans/{scan_id}/bola-check` | Manual BOLA/BFLA run |

Manual `/recon` and `/bola-check` routes are for targeted reruns. They do not
replace the stage-aware `POST /assessments` flow.

## BOLA/BFLA Behavior

BOLA write checks are tied to the documented operation IDs
`api_views.users.update_email`, `api_views.users.update_password`, and
`api_views.users.delete_user`. Each check provisions disposable identities,
performs an attacker attempt, and verifies the effect through an independent
post-condition. A 2xx attempt alone is not a finding.

Read-only BOLA selects authenticated GET endpoints with exactly one
substitutable path parameter. Username parameters are substituted directly.
Numeric/UUID parameters are tested only when the identity's own authenticated
`GET /me` document exposes a unique field matching the parameter; otherwise the
candidate is reported `not_applicable` rather than guessed. Confirmation
requires a successful own-object read carrying the caller's marker, a different
successful cross-object read carrying the target's marker, and no caller marker
in the cross response. Public or marker-less responses are ruled out.

GETs classified as side-effect-prone are never executed.

BFLA is independent of object-level BOLA selection. It requires an operation
whose OpenAPI summary/description says it is administrator-only, a matching
supported execution shape (currently administrator DELETE), and a configured
administrator identity that verifies as an administrator. Missing credentials
or an unverified privilege boundary produces `unsupported`, not a finding.

## Security Safeguards

- URL validation rejects embedded credentials, fragments, dot-segments, and
  unsafe schemes.
- SSRF protections reject private, loopback, link-local, reserved, multicast,
  non-global (including CGNAT), and metadata addresses unless the exact origin
  is explicitly allowlisted.
- Authorized loopback hostnames such as `localhost` may resolve only to
  loopback addresses.
- Assessment validation resolves the target once; spec acquisition and active
  authorization/sensitive-data checks reuse that result, and every connection
  is pinned to the validated addresses.
- Active checks are closed by default and require explicit approval.
- Request execution disables redirects, applies timeouts, and limits response
  size.
- Pinned spec fetching uses a custom HTTPX transport, which disables automatic
  environment-proxy discovery. This is intentional: a proxy could otherwise
  bypass the validated address set. Pinned requests fail closed when a direct
  route is unavailable; proxy integration must be explicit and must not
  re-resolve the target hostname.
- BOLA/BFLA and sensitive-data checks use bounded request budgets.
- Evidence is redacted before persistence; secrets and tokens are not written
  to findings or logs.
- `.env` is local-only and excluded from version control.

## Known Limitations

- Authentication testing is currently unsupported and is not wired into the
  assessment pipeline. The previous experimental authentication-testing module
  was removed because it was incomplete and unsafe to run. Its absence must not
  be interpreted as a completed authentication check.
- Assessment validation pins the target's resolved addresses for the duration
  of the run. If the target changes IP mid-assessment, active checks fail closed
  rather than re-resolving; start a new assessment after the change.
- Active identity provisioning follows the VAmPI-compatible registration and
  login contract (`POST /users/v1/register`, `POST /users/v1/login`) and uses
  `GET /me` for ownership/privilege evidence. Targets with a different auth
  contract can still be inventoried, but active checks may report
  not-applicable or unsupported.
- BOLA write detection is intentionally limited to the three known operation
  shapes. Other mutation endpoints are reported as not applicable rather than
  guessed.
- Read-only BOLA requires a single path identifier and ownership evidence in
  the response. Numeric/UUID checks depend on `GET /me` exposing a matching
  identifier; otherwise they are skipped.
- BFLA currently supports administrator-only DELETE operations only and needs
  an existing administrator identity in `.env`.
- Sensitive-data detection inspects JSON GET responses only; it is not a
  general data-flow or secret-scanning engine.
- Classification is optional and depends on an external LLM provider. A
  missing key or provider failure does not block deterministic checks.
- The optional `langgraph_workflow.py` wrapper is legacy; the supported
  submission and report path is `POST /assessments`.
- The repository contains older script-style test files that perform live
  calls. Do not include them in automated validation.

## Verification Notes

For validation, first use static/import checks, then the focused suites below,
and only afterward a controlled live assessment against `127.0.0.1:5001` if
explicitly approved. Database-backed tests are skipped automatically when
`DATABASE_URL` is unset; when it is set, use only a test database or the
repository's disposable test fixtures.

A safe focused test command, excluding script-style live-call files, is:

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  tests\test_authz_bola_classifier.py `
  tests\test_authz_bola_service.py `
  tests\test_authz_bola_verification.py `
  tests\test_auth_module.py `
  tests\test_db_redaction.py `
  tests\test_recon_classifier.py `
  tests\test_recon_parser.py `
  tests\test_recon_service.py `
  tests\test_request_executor.py `
  tests\test_resource_graph_builder.py `
  tests\test_safe_gets.py `
  tests\test_sensitive_data.py `
  tests\test_target_dns_pinning.py `
  tests\test_pinned_tls.py `
  tests\test_bola_route_security.py `
  tests\test_test_target_authorization.py `
  tests\test_vulnerable_test_api_profile.py -v
```

The DNS-pinning and TLS tests use fake transports or a loopback-only local TLS
server; they do not contact an external network. Do not run the script-style
files (`test_task4.py`, `test_frameworks.py`, `test_workflow.py`,
`test_with_env.py`, and other ad-hoc step scripts) in an automated suite; they
may open database sessions or contact live targets.
