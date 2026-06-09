"""Middleware de logging (socle commun).

Sur chaque requête : extrait IP/UA/path/body, lance les détections US-12
(scanner) et US-10 (exploit), puis émet un event `request` conforme au schéma.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from fastapi import Request, Response

from app.events.builder import build_event, emit
from app.middleware import exploit, scanner


def client_ip(request: Request) -> str:
    """IP source réelle (gère X-Forwarded-For si le honeypot est derrière un proxy)."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


async def log_requests(request: Request, call_next) -> Response:
    """Journalise la requête, détecte scanner + exploit, émet l'event request."""
    body = (await request.body()).decode("utf-8", "replace")[:4096]
    user_agent = request.headers.get("user-agent", "")
    path = request.url.path
    query = request.url.query

    payload: dict[str, Any] = {
        "method": request.method,
        "path": path,
        "user_agent": user_agent,
        "headers": dict(request.headers),
    }
    if body:
        payload["body"] = body
    if scanner.is_scanner(user_agent) or scanner.looks_like_webshell(path):
        payload["is_scanner"] = True

    classification = exploit.detect(
        unquote(path), unquote(query), unquote(body), " ".join(request.headers.values())
    )

    emit(
        build_event(
            event_type="request",
            src_ip=client_ip(request),
            payload=payload,
            src_port=request.client.port if request.client else None,
            classification=classification,
        )
    )
    return await call_next(request)
