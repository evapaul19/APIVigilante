# APIVigilante: API Security Assessment System

## Overview

APIVigilante is an API security assessment system that performs:
- OpenAPI specification discovery and endpoint inventory
- LLM-based risk classification
- BOLA (Broken Object Level Authorization) vulnerability testing
- Resource graph construction
- Persistence of results to PostgreSQL

## Quick Start

### Prerequisites

- Docker Desktop 4.95.0 or later
- Python 3.12+
- 2 GB+ available memory

### 1. Start Infrastructure

Start the PostgreSQL and VAmPI containers:

```bash
docker compose up -d
```

Wait for both containers to turn healthy:
- PostgreSQL on port 5432
- VAmPI on port 5000

### 2. Configure Environment

Copy the example environment file and ensure the following are set:

```bash
cp .env.example .env
```

The `.env` file should contain:

```
DATABASE_URL=postgresql+psycopg://api_security:MyDbPass_82x@localhost:5432/api_security
GEMINI_API_KEY=your_gemini_key_here
OPENROUTER_API_KEY=your_openrouter_key_here
POSTGRES_PASSWORD=MyDbPass_82x
TARGET_BASE_URL=http://localhost:5000
```

**Note:** The `GEMINI_API_KEY` and `OPENROUTER_API_KEY` are required for LLM-based endpoint classification. Without these, the system will discover and persist endpoints but classifications will fail gracefully.

### 3. Start the FastAPI Application

Using the project CLI entry point:

```bash
api-security-system
```

Or using uvicorn directly:

```bash
uv run uvicorn api_security_system.api:app --host 127.0.0.1 --port 8000
```

The API will be available at `http://127.0.0.1:8000`.

### 4. Create a Scan

```bash
curl -X POST http://127.0.0.1:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id": 353}'
```

Target 353 is `bola-test-target` at `http://localhost:5000`. You can list targets with the database queries below.

### 5. Trigger Reconnaissance

```bash
curl -X POST http://127.0.0.1:8000/scans/{scan_id}/recon
```

This will:
- Parse the target's OpenAPI specification
- Persist 14 endpoint inventory records
- Run LLM-based risk classification (requires API keys)

### 6. Authorized BOLA Testing

```bash
curl -X POST http://127.0.0.1:8000/scans/{scan_id}/bola \
  -H "Content-Type: application/json" \
  -d '{"allow_identity_registration": true}'
```

**Important:** The BOLA safety gate requires explicit `allow_identity_registration=true`. This is a security feature - BOLA testing is not enabled by default.

### 7. Retrieve Findings

```bash
curl -X GET http://127.0.0.1:8000/scans/{scan_id}/findings
```

Returns a list of findings with type, severity, status, and evidence references.

### 8. Run the Test Suite

```bash
python -m pytest tests/ -v
```

All 75 tests pass. See `TEST_RESULTS.md` for detailed output.

### 9. Database Queries (admin)

```bash
psql "postgresql+psycopg://api_security:MyDbPass_82x@localhost:5432/api_security" -c "
  SELECT id, status, started_at, completed_at FROM scan ORDER BY id DESC LIMIT 5;
  SELECT id, path, method, risk_classification FROM endpoint ORDER BY id DESC LIMIT 14;
  SELECT id, type, severity, status FROM finding ORDER BY id DESC LIMIT 10;
"
```

## Project Structure

```
api-security-system/
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # PostgreSQL + VAmPI services
├── .env                   # Environment configuration (create from .env.example)
├── .env.example           # Example environment variables
├── pyproject.toml         # Project configuration & CLI entry point
├── src/
│   ├── api_security_system/
│   │   ├── __init__.py    # Entry point: api-security-system command
│   │   ├── api.py         # FastAPI application with 7 routes
│   │   ├── langgraph_workflow.py  # 6-node StateGraph workflow
│   │   ├── recon/
│   │   │   ├── service.py     # Recon orchestration
│   │   ├── parser.py        # OpenAPI spec parsing
│   │   ├── classifier.py    # LLM-based risk classification
│   │   └── schemas.py       # Pydantic models
│   ├── authz_bola/
│   │   ├── service.py     # BOLA orchestration
│   │   └── schemas.py     # BOLA result models
│   ├── llm/               # LLM client utilities
│   ├── request_executor/  # Deterministic HTTP request sender
│   ├── resource_graph/    # Resource graph builder
│   └── db/                # Database engine and session management
├── tests/                 # 75 passing tests
├── targets/               # OpenAPI spec files
├── alemic/                # Database migration history
└── README.md              # This file
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Report application and database health |
| POST | /scans | Create a pending scan for an existing target |
| GET | /scans/{scan_id} | Retrieve a scan's current lifecycle state |
| GET | /scans/{scan_id}/findings | List findings persisted for a scan |
| POST | /scans/{scan_id}/recon | Trigger reconnaissance for a scan |

**BOLA endpoint** (not documented in FastAPI but functional):
- POST /scans/{scan_id}/bola with `{"allow_identity_registration": true}`

## Test Suite

Run all tests:

```bash
python -m pytest tests/ -v
```

**Result:** 75 passed, 0 failed, 0 errors

## Environment Variables

| Variable | Required | Default/Description |
|----------|----------|---------------------|
| `DATABASE_URL` | Yes | `postgresql+psycopg://api_security:MyDbPass_82x@localhost:5432/api_security` |
| `GEMINI_API_KEY` | Yes (for LLM classification) | Your Google Gemini API key |
| `OPENROUTER_API_KEY` | Yes (for LLM classification) | Your OpenRouter API key |
| `POSTGRES_PASSWORD` | Yes | `MyDbPass_82x` |
| `TARGET_BASE_URL` | Yes | `http://localhost:5000` |

## Docker Compose

```bash
docker compose up -d
```

Services:
- `api-security-system-postgres-1`: PostgreSQL 17 on port 5432
- `vampi`: VAmPI API on port 5000

## MCP Server

The project includes MCP (Multi-Command Protocol) server support for integration with AI assistants. The MCP server can be started with:

```bash
python -m mcp_server
```

(See `mcp_server.py` for implementation details - this is an optional addon.)

## Limitations

- LLM classification requires `GEMINI_API_KEY` and `OPENROUTER_API_KEY` environment variables
- BOLA testing requires explicit `allow_identity_registration=true` parameter
- In-memory checkpoint resume: workflow state is checkpointed within the same process; cross-process resume requires external checkpoint storage (Redis/postgres)
- The `api-security-system` CLI command starts the FastAPI server; the `uvicorn` command is an alternative