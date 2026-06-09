"""Honeypot HTTP — application FastAPI émulant un WordPress (Epic 2).

Pipeline de traitement :
  1. middleware log_requests : journalise chaque requête, détecte scanners (US-12)
     et exploits (US-10), émet un event `request`.
  2. middleware add_coherent_headers : injecte les headers Apache/PHP cohérents
     + le header Link (api.w.org) d'un vrai WordPress.
  3. routeurs : wordpress (US-08), extra (US-28), credentials (US-09), canary (US-11).

Anti-détection : docs/openapi de FastAPI désactivés, 404 rendu en page WordPress
(pas de JSON FastAPI), header `server: uvicorn` supprimé (cf. server_header=False
/ --no-server-header dans le Dockerfile).
"""

import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import COHERENT_HEADERS, LISTEN_PORT
from app.middleware.logging import log_requests
from app.routes import canary, credentials, extra, wordpress

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _read_template(name: str, fallback: str) -> str:
    try:
        return (_TEMPLATE_DIR / name).read_text(encoding="utf-8")
    except OSError:
        return fallback


_NOT_FOUND_HTML = _read_template(
    "404.html", "<!DOCTYPE html><html><body><h1>Page not found</h1></body></html>"
)

app = FastAPI(title="wordpress", docs_url=None, redoc_url=None, openapi_url=None)

app.include_router(wordpress.router)
app.include_router(extra.router)
app.include_router(credentials.router)
app.include_router(canary.router)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
    """Évite le JSON FastAPI : rend des réponses cohérentes Apache/WordPress."""
    if exc.status_code == 404:
        return HTMLResponse(_NOT_FOUND_HTML, status_code=404)
    return PlainTextResponse(str(exc.detail or ""), status_code=exc.status_code)


@app.middleware("http")
async def add_coherent_headers(request: Request, call_next) -> Response:
    """Injecte Server / X-Powered-By + le header Link WordPress sur chaque réponse."""
    response = await call_next(request)
    for name, value in COHERENT_HEADERS.items():
        response.headers[name] = value
    host = request.headers.get("host")
    if host:
        response.headers["Link"] = f'<http://{host}/wp-json/>; rel="https://api.w.org/"'
        # Un vrai WordPress annonce son endpoint pingback.
        response.headers["X-Pingback"] = f"http://{host}/xmlrpc.php"
    return response


# Enregistré après le middleware de headers => s'exécute en premier (lit la requête brute).
app.middleware("http")(log_requests)


def main() -> None:
    host = os.getenv("HTTP_HOST", "127.0.0.1")
    # server_header=False : pas de fuite "server: uvicorn" (le middleware met Apache).
    uvicorn.run(app, host=host, port=LISTEN_PORT, server_header=False)


if __name__ == "__main__":
    main()
