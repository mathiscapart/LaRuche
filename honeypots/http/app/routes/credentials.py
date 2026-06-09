"""Capture des credentials soumis sur les faux formulaires (US-09).

Les POST sur les routes de login extraient username/password et émettent un
event credential_attempt conforme au schéma.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.events.builder import build_event, emit
from app.middleware.logging import client_ip

router = APIRouter()

# Champs de formulaire usuels selon la plateforme émulée (WP, admin générique, phpMyAdmin).
_USER_FIELDS = ("log", "username", "user", "pma_username", "email")
_PASS_FIELDS = ("pwd", "password", "pass", "pma_password")


def _pick(form: dict[str, str], fields: tuple[str, ...]) -> str:
    for field in fields:
        value = form.get(field)
        if isinstance(value, str) and value:
            return value
    return ""


async def _capture(request: Request) -> None:
    form = dict(await request.form())
    payload = {
        "method": "POST",
        "path": request.url.path,
        "username": _pick(form, _USER_FIELDS),
        "password": _pick(form, _PASS_FIELDS),
        "user_agent": request.headers.get("user-agent", ""),
    }
    emit(
        build_event(
            event_type="credential_attempt",
            src_ip=client_ip(request),
            payload=payload,
            src_port=request.client.port if request.client else None,
        )
    )


@router.post("/wp-login.php", response_class=HTMLResponse)
async def wp_login_post(request: Request) -> HTMLResponse:
    await _capture(request)
    # WordPress réaffiche le login avec un message d'erreur générique.
    return HTMLResponse(
        '<div id="login_error">Error: The password you entered is incorrect.</div>',
        status_code=200,
    )


@router.post("/admin/login", response_class=HTMLResponse)
@router.post("/phpmyadmin", response_class=HTMLResponse)
@router.post("/phpmyadmin/index.php", response_class=HTMLResponse)
async def generic_login_post(request: Request) -> HTMLResponse:
    await _capture(request)
    return HTMLResponse("<p>Access denied for this user.</p>", status_code=200)
