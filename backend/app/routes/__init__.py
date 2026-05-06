from __future__ import annotations

from importlib import import_module

from fastapi import FastAPI


_ROUTE_MODULES = ("auth", "files", "dam", "analytics", "system", "siem", "reports", "ws")

def include_all_routers(app: FastAPI) -> None:
    for module_name in _ROUTE_MODULES:
        try:
            module = import_module(f"{__name__}.{module_name}")
        except ModuleNotFoundError:
            continue

        router = getattr(module, "router", None)
        if router is not None:
            app.include_router(router)
