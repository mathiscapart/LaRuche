"""Honeypot HTTP — application FastAPI émulant un WordPress (Epic 2).

Pipeline de traitement :
  1. middleware log_requests : journalise chaque requête, détecte scanners (US-12)
     et exploits (US-10), émet un event `request`.
  2. middleware add_coherent_headers : injecte les headers Apache/PHP cohérents.
  3. routeurs : wordpress (US-08), extra (US-28), credentials (US-09), canary (US-11).

Les endpoints docs/openapi de FastAPI sont désactivés : un vrai WordPress ne les
exposerait pas (tell de honeypot évité).
"""

import os

import uvicorn
from fastapi import FastAPI, Request, Response

from app.config import COHERENT_HEADERS, LISTEN_PORT
from app.middleware.logging import log_requests
from app.routes import canary, credentials, extra, wordpress

app = FastAPI(title="wordpress", docs_url=None, redoc_url=None, openapi_url=None)

app.include_router(wordpress.router)
app.include_router(extra.router)
app.include_router(credentials.router)
app.include_router(canary.router)


@app.middleware("http")
async def add_coherent_headers(request: Request, call_next) -> Response:
    """Injecte Server / X-Powered-By cohérents sur chaque réponse."""
    response = await call_next(request)
    for name, value in COHERENT_HEADERS.items():
        response.headers[name] = value
    return response


# Enregistré après le middleware de headers => s'exécute en premier (lit la requête brute).
app.middleware("http")(log_requests)


def main() -> None:
    host = os.getenv("HTTP_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=LISTEN_PORT)


if __name__ == "__main__":
    main()
