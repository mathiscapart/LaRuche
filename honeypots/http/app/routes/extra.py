"""Routes supplémentaires ciblées par les scanners Internet (US-28).

Chaque route renvoie une réponse crédible (faux fichiers, fausses pages). Les
headers cohérents sont ajoutés globalement par le middleware de main.py.
"""

from __future__ import annotations

import html
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
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


def _phpinfo_variables(request: Request) -> str:
    """Construit la table $_SERVER de phpinfo à partir de la VRAIE requête.

    Reflète User-Agent, query string, IP, méthode et en-têtes : un phpinfo
    statique qui ne renvoie pas la requête de l'attaquant est un tell classique
    de honeypot.
    """
    client = request.client
    query = request.url.query
    uri = request.url.path + (f"?{query}" if query else "")
    now = time.time()
    rows: list[str] = []

    def add(key: str, value: object) -> None:
        text = html.escape(str(value)) if value not in (None, "") else "<i>no value</i>"
        rows.append(f"<tr><td class=\"e\">$_SERVER['{key}'] </td><td class=\"v\">{text} </td></tr>")

    # En-têtes HTTP réels de la requête (format HTTP_NOM, comme un vrai PHP).
    for name, value in request.headers.items():
        add("HTTP_" + name.upper().replace("-", "_"), value)
    add("PATH", "/usr/local/bin:/usr/bin:/bin")
    add("SERVER_SIGNATURE", "")
    add("SERVER_SOFTWARE", "Apache/2.4.57 (Debian)")
    add("SERVER_NAME", request.headers.get("host", "localhost").split(":")[0])
    add("SERVER_ADDR", "172.18.0.7")
    add("SERVER_PORT", "80")
    add("REMOTE_ADDR", client.host if client else "127.0.0.1")
    add("DOCUMENT_ROOT", "/var/www/html")
    add("REQUEST_SCHEME", request.url.scheme or "http")
    add("SERVER_ADMIN", "webmaster@localhost")
    add("SCRIPT_FILENAME", "/var/www/html" + request.url.path)
    add("REMOTE_PORT", client.port if client else 0)
    add("GATEWAY_INTERFACE", "CGI/1.1")
    add("SERVER_PROTOCOL", "HTTP/1.1")
    add("REQUEST_METHOD", request.method)
    add("QUERY_STRING", query)
    add("REQUEST_URI", uri)
    add("SCRIPT_NAME", request.url.path)
    add("PHP_SELF", request.url.path)
    add("REQUEST_TIME_FLOAT", f"{now:.4f}")
    add("REQUEST_TIME", int(now))
    return "\n".join(rows)


@router.get("/phpinfo.php", response_class=HTMLResponse)
async def phpinfo(request: Request) -> HTMLResponse:
    page = _read(_TEMPLATE_DIR, "phpinfo.html").replace(
        "<!--PHP_VARIABLES-->", _phpinfo_variables(request)
    )
    return HTMLResponse(page)


@router.get("/api/v1/users")
async def api_users() -> JSONResponse:
    return JSONResponse([{"id": 1, "username": "admin", "role": "administrator"}])


@router.get("/phpmyadmin", response_class=HTMLResponse)
@router.get("/phpmyadmin/index.php", response_class=HTMLResponse)
async def phpmyadmin() -> HTMLResponse:
    return HTMLResponse(_read(_TEMPLATE_DIR, "phpmyadmin.html"))


@router.get("/console")
async def console() -> None:
    # 403 rendu en page d'erreur Apache par le handler global (pas du plaintext).
    raise HTTPException(status_code=403)
