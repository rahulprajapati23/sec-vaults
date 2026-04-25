from __future__ import annotations

from fastapi import FastAPI
from . import auth, files, dam, analytics

def include_all_routers(app: FastAPI) -> None:
    app.include_router(auth.router)
    app.include_router(files.router)
    app.include_router(dam.router)
    app.include_router(analytics.router)
