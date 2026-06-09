"""Honeypot HTTP — application FastAPI émulant un WordPress (Epic 2, US-08).

Un middleware injecte des headers cohérents (Apache/PHP) sur chaque réponse pour
rester crédible face aux scanners. Les routes WordPress sont montées depuis
app.routes.wordpress. Les endpoints internes de FastAPI (docs/openapi) sont
désactivés : un vrai WordPress ne les exposerait pas (tell de honeypot évité).
"""

import os

import uvicorn
from fastapi import FastAPI, Request, Response

from app.config import COHERENT_HEADERS, LISTEN_PORT
from app.routes import wordpress

app = FastAPI(title="wordpress", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(wordpress.router)


@app.middleware("http")
async def add_coherent_headers(request: Request, call_next) -> Response:
    """Injecte Server / X-Powered-By cohérents sur chaque réponse."""
    response = await call_next(request)
    for name, value in COHERENT_HEADERS.items():
        response.headers[name] = value
    return response


def main() -> None:
    host = os.getenv("HTTP_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=LISTEN_PORT)


if __name__ == "__main__":
    main()
