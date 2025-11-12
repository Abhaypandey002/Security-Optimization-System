from __future__ import annotations

import logging
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import routes
from app.core.config import get_settings

settings = get_settings()

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    application = FastAPI(title=settings.app_name)

    application.include_router(routes.api_router, prefix=settings.api_prefix)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.middleware("http")
    async def enforce_https_middleware(request: Request, call_next):
        if settings.enforce_https and request.url.scheme != "https":
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": "HTTPS required"})
        return await call_next(request)

    return application


app = create_app()
