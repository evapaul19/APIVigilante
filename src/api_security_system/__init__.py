"""Entry point for the API security assessment system."""

import os

from api_security_system.api import app

import uvicorn


def main() -> None:
    """Start the FastAPI application using uvicorn."""
    port = int(os.getenv("API_PORT", "8000"))
    host = os.getenv("API_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=port, reload=False)
