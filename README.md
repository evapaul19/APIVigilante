# APIVigilante: API Security Assessment System

APIVigilante is an OpenAPI-driven API security assessment prototype. Users
supply the target base URL and OpenAPI document URL at runtime; the workflow
does not substitute a fixed API. It discovers endpoints from that target's
specification, builds a deterministic resource graph, runs supported checks
where the target is authorized, and persists sanitized evidence and stage-aware
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
`allow_identity_registration=true` on `POST /assessments`, plus either an
explicitly allowlisted origin or both an operator opt-in
(`APIVIGILANTE_ALLOW_USER_AUTHORIZED_TARGETS=1`) and
`authorized_for_active_testing=true` for that assessment. Other targets can be
inventoried, but active checks are reported as `not_supported`. Callers may
supply an `auth_profile` for targets that do not use VAmPI's auth contract.

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
root even when the process is started from another directory. Environment
values are read when the API process starts, so restart the API after changing
`.env`.

### Browser frontend origins

The API allows the local Vite origins `http://localhost:5173` and
`http://127.0.0.1:5173` by default. Set `APIVIGILANTE_CORS_ORIGINS` to a
comma-separated list of exact frontend origins in other environments; wildcard
origins are rejected. Restart the API after changing this setting.

```dotenv
APIVIGILANTE_CORS_ORIGINS=https://app.example.com
```

### Authorized target origins

The target and spec URLs are always supplied through `POST /assessments`.
Public targets that pass SSRF validation can be inventoried without editing
source code. Active checks are additionally limited to exact allowlisted
origins:

- `http://localhost:5000` (the bundled VAmPI-compatible contract).
- Exact additional origins configured by the operator. These origins must
  still resolve exclusively to public addresses:

```dotenv
APIVIGILANTE_AUTHORIZED_ORIGINS=https://api.example.com
```

- Exact local test origins only when explicit test mode is enabled:

```dotenv
APIVIGILANTE_ENABLE_TEST_TARGET=1
APIVIGILANTE_TEST_TARGET_ORIGINS=http://127.0.0.1:5001,http://127.0.0.1:5010
```

`APIVIGILANTE_TEST_TARGET_ORIGINS` replaces the bundled
`http://127.0.0.1:5001` default; omitting it keeps the default. Origins are
exact `scheme://host[:port]` values. The local test-target exception accepts
only loopback resolutions; it does not authorize private-network, link-local,
or cloud metadata addresses. The built-in VAmPI-compatible
`http://localhost:5000` origin is also restricted to loopback resolutions.
Do not expose the isolated test API beyond loopback.

Active authorization checks without an `auth_profile` require the target's
OpenAPI document to expose the supported `POST /users/v1/register` and
`POST /users/v1/login` contract. For other targets, supply an `auth_profile`
with two identities to run read-only BOLA checks on authenticated GET endpoints
that have one or more path parameters. Every path parameter needs a value for
both identities. Generic BFLA is reported `not_supported`; VAmPI BFLA still
requires the existing administrator/identity contract.

An `auth_profile` can use static bearer, Basic, API-key, or custom headers, or a
generic JSON login response. For static identities use `type: "static"` and
provide `token`, `api_key`, `username`/`password`, or explicit `headers`.
Profile-level `extra_headers` are sent on login and authenticated requests, for
targets that also require tenant, API-version, or login API-key headers.
Example login profile:

```json
{
  "type": "login",
  "scheme": "bearer",
  "login_path": "/auth/login",
  "login_username_field": "username",
  "login_password_field": "password",
  "token_path": "access_token",
  "extra_headers": {"X-Tenant": "tenant-a"},
  "identities": [
    {"label": "attacker", "username": "alice", "password": "alice-password",
     "path_values": {"id": "1"}},
    {"label": "victim", "username": "bob", "password": "bob-password",
     "path_values": {"id": "2"}}
  ]
}
```

Secrets are held in `SecretStr` fields and redacted from repr/log output and
persisted test executions. Persisted evidence redacts headers by sensitive
header name (`authorization`, `cookie`, names containing `token`, `key`,
`secret`, or `password`); use such a name for secret-valued custom or extra
headers rather than an innocuous one. Profiles never synthesize credentials or
guess auth endpoints; missing or invalid values fail closed. Sensitive-data
checks use one profile identity (or an explicit anonymous `type: "none"`
profile) and inspect GET responses only. When building a profile in PowerShell,
pass `-Depth 10` to `ConvertTo-Json` so nested identity fields are not
flattened.

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

### Option A: full stack with Docker Compose (recommended)

`docker compose up --build` starts PostgreSQL, applies migrations once, starts
the API, and serves the production frontend build through nginx. The browser
calls the API through the same-origin `/api/` proxy, so the bundled deployment
does not depend on CORS configuration.

```powershell
docker compose up --build
```

- Frontend: `http://localhost:8080`
- API through the frontend proxy: `http://localhost:8080/api/health`
- API directly: `http://localhost:8000`
- PostgreSQL: `localhost:${POSTGRES_PORT:-5432}`

Set `POSTGRES_PASSWORD` in `.env` before starting the stack. `POSTGRES_PORT`
defaults to 5432; set `POSTGRES_PORT=5433` when another PostgreSQL already uses
5432. `BACKEND_PORT`, `FRONTEND_PORT`, and `VITE_API_BASE_URL` are also
configurable.

The one-shot `migrate` service runs `alembic upgrade head` and exits. The
`backend` service starts only after that succeeds, and `frontend` starts only
after the backend passes its `/health` check.

An optional bundled test target is available under the `test` profile. It is
never part of the default stack:

```powershell
docker compose --profile test up --build
```

The profile runs `vulnerable_test_api` in the backend container's network
namespace at `127.0.0.1:5001`, which is the only origin the test-only allowlist
accepts. It is intentionally vulnerable and must never be exposed.

### Option B: PostgreSQL only (local development)

The Compose file can still start just PostgreSQL:

```powershell
docker compose up -d postgres
docker compose ps
docker compose exec postgres pg_isready -U api_security
```

PostgreSQL connection attempts are bounded to two seconds each and health SQL
has a five-second statement timeout. `/health` returns HTTP 503 with a database
readiness message when the database cannot be reached.

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
`9b6d2e4c1a10` (adds the `partial` scan status on top of the
`assessment_stages` table). Run from the project root so the root `.env` is
loaded:

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
acquires the spec (or performs bounded same-origin HTML-link inventory when
the optional spec is unavailable), runs recon, optionally classifies endpoints, builds the
resource graph, and runs supported active checks when explicitly approved.
HTML-link discovery is intentionally not comprehensive; unlinked API routes
remain outside its coverage and are reported as a limitation.

The HTTP endpoint is asynchronous: it validates the target, creates the scan,
and returns `201` with `scan_id` and `status: "pending"` immediately. The stage
pipeline then runs in the background. Poll `GET /scans/{scan_id}` until the
status is `completed`, `partial`, or `failed`, then read the report.
`GET /scans/{scan_id}/report` returns `409` while the scan is pending or
running, so an in-progress result is never mistaken for a final report. Calling
the service function directly (without FastAPI background tasks) still runs
synchronously for tests.

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

For a public target that is not origin-allowlisted, the operator must also set
`APIVIGILANTE_ALLOW_USER_AUTHORIZED_TARGETS=1`, and the request must set
`authorized_for_active_testing = $true`. Supply `auth_profile` using the shape
shown above when the target does not implement VAmPI's auth contract.

A different user-supplied target with a custom spec path needs no code changes:

```powershell
$body = @{
  base_url = "https://api.example.com/v2"
  openapi_spec_url = "https://api.example.com/v2/metadata/openapi.yaml"
  target_name = "customer-api"
  classify = $false
  allow_identity_registration = $false
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/assessments" `
  -ContentType "application/json" `
  -Body $body
```

Replace the example host with any target permitted by the SSRF policy. The
response records that target's `base_url`, `spec_source`, endpoint inventory,
and each check's actual outcome. Active checks for a target without an
explicit active-check authorization or without the supported identity contract
are reported `not_supported` or `unsupported`, not treated as clean.

Notes:

- `request_budget` is 1-100.
- BOLA/BFLA and sensitive-data checks share that budget. Sensitive inspection
  receives only what BOLA/BFLA did not use and is additionally capped at 20.
- `openapi_spec_url` may use any same-origin path. When omitted, common
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
- `summary`: plain-language `headline`, `verdict`, `coverage`, confirmed and
  candidate counts, and limitations. It is generated only from persisted rows.
- `findings[].title`, `category_label`, `what_happened`, `why_it_matters`,
  `impact`, `remediation`, `severity_reasoning`: human-readable context derived
  from the finding category, status, and recorded evidence. The findings
  endpoint returns the same fields, so the two views cannot disagree.

A scan that produced an inventory but had a security stage fail is persisted as
`partial`, not `completed`. A `failed` scan is also terminal; its report is
available but must not be read as complete coverage.

Stage statuses are intentionally explicit: `passed`, `succeeded`, `completed`,
`built`, `performed`, `not_requested`, `not_run`, `not_applicable`,
`unsupported`, `not_supported`, `partial`, `stopped_early`, or `failed`.
Check-level report statuses also distinguish `finding_confirmed`, `candidate`,
and `ran_no_finding` from checks that did not run.
Finding statuses are `candidate`, `confirmed`, or `false_positive`. Finding
types are `bola`, `bfla`, or `sensitive_data`.

Legacy scans without stage rows still return a report using
`stage_source: "legacy_fallback"`. Missing active-check evidence is not treated
as a clean result.

## API Routes

| Method | Route | Purpose |
|--------|-------|---------|
| GET | `/health` | Application and database health |
| POST | `/assessments` | Validate a target, create a scan, and run the assessment in the background (`201`, `status: pending`) |
| POST | `/scans` | Create a pending scan for an existing target |
| GET | `/scans/{scan_id}` | Scan lifecycle status (`pending`, `running`, `completed`, `partial`, `failed`) |
| GET | `/scans/{scan_id}/findings` | Persisted findings with human-readable context and evidence references |
| GET | `/scans/{scan_id}/report` | Full report with summary, stage outcomes, and evidence; `409` while running |
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
- Target and spec URLs are runtime input; assessment orchestration passes the
  selected URL through validation, spec acquisition, recon, and checks.
- Assessment validation resolves the target once; spec acquisition and active
  authorization/sensitive-data checks reuse that result, and every connection
  is pinned to the validated addresses.
- Active checks are closed by default and require explicit approval. They are
  also limited to exact operator-authorized origins and the supported identity
  contract; unsupported targets are reported, not guessed.
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

- Authentication testing remains limited: the pipeline can send caller-supplied
  static or login-derived credentials and inspect responses, but it does not
  perform password-policy, MFA, session-fixation, or token-lifecycle testing.
  A profile with missing/invalid credentials fails closed and is not evidence
  of a completed authentication review.
- Assessment validation pins the target's resolved addresses for the duration
  of the run. If the target changes IP mid-assessment, active checks fail closed
  rather than re-resolving; start a new assessment after the change.
- Without an `auth_profile`, active identity provisioning follows the
  VAmPI-compatible registration and login contract (`POST /users/v1/register`,
  `POST /users/v1/login`) and uses `GET /me` for ownership/privilege evidence.
  With a profile, caller-supplied identities are used instead; every path
  parameter must have an explicit value for both identities. Targets without a
  profile or supported VAmPI contract can still be inventoried, but active
  checks may report not-applicable or unsupported.
- BOLA write detection is intentionally limited to the three known operation
  shapes. Other mutation endpoints are reported as not applicable rather than
  guessed.
- VAmPI read-only BOLA requires a single path identifier and ownership evidence
  in the response. Generic profiles can test authenticated GET endpoints with
  multiple path parameters, but both identities must supply every value.
  Numeric/UUID VAmPI checks depend on `GET /me` exposing a matching identifier;
  otherwise they are skipped.
- Active authorization checks use either the VAmPI-compatible
  registration/login contract or an explicit `auth_profile`. Generic profiles
  support read-only BOLA only and report BFLA `not_supported`; the system does
  not guess auth endpoints or synthesize credentials. Profiles cannot express
  multiple roles for the same identity, so BFLA remains VAmPI-specific. Profile
  BOLA selection requires an operation-level OpenAPI `security` requirement;
  a document-wide requirement alone is not inherited.
- BFLA currently supports administrator-only DELETE operations only and needs
  an existing administrator identity in `.env`.
- Sensitive-data detection inspects JSON GET responses only; it is not a
  general data-flow or secret-scanning engine. It uses one `auth_profile`
  identity when supplied, otherwise the VAmPI contract or unauthenticated GET
  responses; it does not probe multiple profile identities.
- Classification is optional and depends on an external LLM provider. A
  missing key or provider failure does not block deterministic checks.
- The optional `langgraph_workflow.py` wrapper is legacy; the supported
  submission and report path is `POST /assessments`.
- The repository contains older script-style test files that perform live
  calls. Do not include them in automated validation.

## Verification Notes

For validation, first use static/import checks, then the focused suites below,
then a controlled live assessment against the local synthetic API in explicit
test mode, and finally a user-supplied permitted target with an accessible
OpenAPI document. Database-backed tests are skipped automatically when
`DATABASE_URL` is unset; when it is set, use only a test database or the
repository's disposable test fixtures.

A safe focused test command, excluding script-style live-call files, is:

```powershell
& .\.venv\Scripts\python.exe -m pytest `
  tests\test_authz_bola_classifier.py `
  tests\test_authz_bola_service.py `
  tests\test_authz_bola_verification.py `
  tests\test_auth_module.py `
  tests\test_auth_profiles.py `
  tests\test_profile_bola_service.py `
  tests\test_zero_finding_report.py `
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
  tests\test_user_defined_targets.py `
  tests\test_vulnerable_test_api_profile.py -v
```

The DNS-pinning and TLS tests use fake transports or a loopback-only local TLS
server; they do not contact an external network. Do not run the script-style
files (`test_task4.py`, `test_frameworks.py`, `test_workflow.py`,
`test_with_env.py`, and other ad-hoc step scripts) in an automated suite; they
may open database sessions or contact live targets.
