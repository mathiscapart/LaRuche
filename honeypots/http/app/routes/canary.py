"""Canary /.env (US-11).

Sert un faux fichier .env à credentials décoy et émet un événement
`canary_triggered` de sévérité CRITICAL (JSONL → Fluent Bit, US-17).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from app.events.builder import build_event, emit
from app.middleware.logging import client_ip

router = APIRouter()

_ENV_DECOY = Path(__file__).resolve().parent.parent / "decoys" / "env.decoy"
_TRAP_NAME = "dotenv_canary"


@router.get("/.env", response_class=PlainTextResponse)
async def dotenv_canary(request: Request) -> PlainTextResponse:
    try:
        content = _ENV_DECOY.read_text(encoding="utf-8")
    except OSError:
        content = ""
    event = build_event(
        event_type="canary_triggered",
        src_ip=client_ip(request),
        payload={
            "method": "GET",
            "path": "/.env",
            "user_agent": request.headers.get("user-agent", ""),
            "trap": _TRAP_NAME,
        },
        src_port=request.client.port if request.client else None,
        classification={
            "category": "CANARY_TRIGGERED",
            "severity": "critical",
            "tags": [_TRAP_NAME],
        },
    )
    emit(event)
    return PlainTextResponse(content)
