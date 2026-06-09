"""Routes supplémentaires ciblées par les scanners Internet (US-28).

Chaque route renvoie une réponse crédible (faux fichiers, fausses pages). Les
headers cohérents sont ajoutés globalement par le middleware de main.py.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

router = APIRouter()

_APP_DIR = Path(__file__).resolve().parent.parent
_DECOY_DIR = _APP_DIR / "decoys"
_TEMPLATE_DIR = _APP_DIR / "templates"


def _read(directory: Path, name: str) -> str:
    try:
        return (directory / name).read_text(encoding="utf-8")
    except OSError:
        return ""


@router.get("/.git/config", response_class=PlainTextResponse)
async def git_config() -> PlainTextResponse:
    return PlainTextResponse(_read(_DECOY_DIR, "git-config.decoy"))


@router.get("/phpinfo.php", response_class=HTMLResponse)
async def phpinfo() -> HTMLResponse:
    return HTMLResponse(_read(_TEMPLATE_DIR, "phpinfo.html"))


@router.get("/api/v1/users")
async def api_users() -> JSONResponse:
    return JSONResponse([{"id": 1, "username": "admin", "role": "administrator"}])


@router.get("/phpmyadmin", response_class=HTMLResponse)
@router.get("/phpmyadmin/index.php", response_class=HTMLResponse)
async def phpmyadmin() -> HTMLResponse:
    return HTMLResponse(_read(_TEMPLATE_DIR, "phpmyadmin.html"))


@router.get("/console")
async def console() -> PlainTextResponse:
    # 403 crédible (header Server cohérent ajouté par le middleware global).
    return PlainTextResponse("Forbidden", status_code=403)
