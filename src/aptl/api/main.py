"""FastAPI application factory for the APTL web API."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aptl.api.routers import config, lab, scenarios


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="APTL Web API",
        description="Advanced Purple Team Lab — Web Interface API",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://localhost:5173",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(lab.router, prefix="/api")
    app.include_router(scenarios.router, prefix="/api")
    app.include_router(config.router, prefix="/api")

    @app.get("/api/health")
    async def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
