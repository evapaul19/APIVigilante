# Backend image: FastAPI assessment API plus Alembic migrations.
#
# The same image is used for the one-shot `migrate` service and the long-lived
# `backend` service so migrations and the application always run identical code.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# uv installs the locked dependency set deterministically from uv.lock.
RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./

RUN uv sync --frozen --no-dev --no-editable

ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000

# The database must be migrated first; docker compose runs `migrate` before
# starting this service. The container itself only serves the API.
CMD ["uvicorn", "api_security_system.api:app", "--host", "0.0.0.0", "--port", "8000"]
