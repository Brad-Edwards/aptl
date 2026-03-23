"""FastAPI application factory for the APTL web API."""

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from aptl.api.deps import ALLOWED_ORIGINS
from aptl.api.routers import config, kill, lab, scenarios, terminal
from aptl.utils.logging import get_logger, setup_logging

log = get_logger("api")


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security headers to all responses."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    setup_logging()
    log.info("Creating APTL web API application")

    app = FastAPI(
        title="APTL Web API",
        description="Advanced Purple Team Lab — Web Interface API",
        version="0.1.0",
    )

    app.add_middleware(_SecurityHeadersMiddleware)

    app.add_middleware(  # NOSONAR — localhost-only origins; this is a local lab tool, not internet-facing
        CORSMiddleware,
        allow_origins=list(ALLOWED_ORIGINS),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Accept"],
    )

    app.include_router(lab.router, prefix="/api")
    app.include_router(scenarios.router, prefix="/api")
    app.include_router(config.router, prefix="/api")
    app.include_router(terminal.router, prefix="/api")
    app.include_router(kill.router, prefix="/api")

    @app.get("/api/health")
    async def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
