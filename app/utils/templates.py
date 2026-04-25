from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates


def load_templates() -> Jinja2Templates:
    return Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))
