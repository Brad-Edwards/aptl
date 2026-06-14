"""FastAPI application factory for the APTL web API."""

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aptl.api.deps import ALLOWED_ORIGINS, load_web_auth, verify_token
from aptl.api.routers import config, kill, lab, terminal
from aptl.utils.logging import get_logger, setup_logging

log = get_logger("api")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    setup_logging()
    log.info("Creating APTL web API application")

    # logs CRITICAL and returns None when APTL_API_TOKEN is absent
    load_web_auth()

    app = FastAPI(
        title="APTL Web API",
        description="Advanced Purple Team Lab — Web Interface API",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(ALLOWED_ORIGINS),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Accept", "Authorization"],
    )

    _auth = [Depends(verify_token)]

    app.include_router(lab.router, prefix="/api", dependencies=_auth)
    app.include_router(config.router, prefix="/api", dependencies=_auth)
    app.include_router(terminal.router, prefix="/api", dependencies=_auth)
    app.include_router(kill.router, prefix="/api", dependencies=_auth)

    @app.get("/api/health", dependencies=_auth)
    async def health() -> dict[str, str]:
        """Return a liveness indicator for the web API."""
        return {"status": "ok"}

    return app


app = create_app()
