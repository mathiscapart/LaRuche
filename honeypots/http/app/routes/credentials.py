"""Capture des credentials + faux login WordPress (US-09 + hardening).

Tout POST de login (formulaire ou XML-RPC) émet un `credential_attempt`. Un
couple faible autorisé (config.ALLOWED_WP_CREDENTIALS) simule un login réussi
(`auth_success` + cookie + faux /wp-admin). Les erreurs de login distinguent
"utilisateur inconnu" de "mot de passe incorrect" comme un vrai WordPress
(comportement exploité pour l'énumération). Accepter n'importe quoi serait un tell.
"""

from __future__ import annotations

import html
import re

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.config import ALLOWED_WP_CREDENTIALS, LOGGED_IN_COOKIE
from app.events.builder import build_event, emit
from app.middleware.logging import client_ip
from app.routes.wordpress import render_login

router = APIRouter()

_USER_FIELDS = ("log", "username", "user", "pma_username", "email")
_PASS_FIELDS = ("pwd", "password", "pass", "pma_password")

# Usernames "connus" => message d'erreur distinct (énumération réaliste).
_KNOWN_USERS = {user for user, _ in ALLOWED_WP_CREDENTIALS} | {"editor"}

_XMLRPC_METHOD = re.compile(r"<methodName>\s*([\w.]+)\s*</methodName>", re.IGNORECASE)
_XMLRPC_STRING = re.compile(r"<string>(.*?)</string>", re.IGNORECASE | re.DOTALL)
# Chaînes qui sont des noms de méthode (à ignorer pour trouver user/pass).
_METHOD_LIKE = re.compile(r"^(system|wp|mt|metaWeblog|blogger|demo|pingback)\.", re.IGNORECASE)
_XMLRPC_FAULT = (
    '<?xml version="1.0"?><methodResponse><fault><value><struct>'
    "<member><name>faultCode</name><value><int>403</int></value></member>"
    "<member><name>faultString</name><value><string>Incorrect username or password.</string>"
    "</value></member></struct></value></fault></methodResponse>"
)


def _pick(form: dict[str, str], fields: tuple[str, ...]) -> str:
    for field in fields:
        value = form.get(field)
        if isinstance(value, str) and value:
            return value
    return ""


def _emit(
    request: Request,
    event_type: str,
    username: str,
    password: str,
    classification: dict | None = None,
    extra: dict | None = None,
) -> None:
    payload = {
        "method": "POST",
        "path": request.url.path,
        "username": username,
        "password": password,
        "user_agent": request.headers.get("user-agent", ""),
    }
    if extra:
        payload.update(extra)
    emit(
        build_event(
            event_type=event_type,
            src_ip=client_ip(request),
            payload=payload,
            src_port=request.client.port if request.client else None,
            classification=classification,
        )
    )


def _login_error(username: str) -> str:
    if username in _KNOWN_USERS:
        return (
            f'<div id="login_error"><strong>Error:</strong> The password you entered for the '
            f"username <strong>{html.escape(username)}</strong> is incorrect.</div>"
        )
    return (
        '<div id="login_error"><strong>Error:</strong> Unknown username. '
        "Check again or try your email address.</div>"
    )


@router.post("/wp-login.php")
async def wp_login_post(request: Request) -> Response:
    form = dict(await request.form())
    username = _pick(form, _USER_FIELDS)
    password = _pick(form, _PASS_FIELDS)
    _emit(request, "credential_attempt", username, password)

    if (username, password) in ALLOWED_WP_CREDENTIALS:
        # Login "réussi" : on laisse entrer dans un faux wp-admin pour observer la suite.
        _emit(
            request,
            "auth_success",
            username,
            password,
            classification={"category": "BRUTE_FORCE", "severity": "high", "tags": ["valid_login"]},
        )
        response = RedirectResponse("/wp-admin/", status_code=302)
        response.set_cookie(LOGGED_IN_COOKIE, f"{username}|fake", path="/", httponly=True)
        return response

    return HTMLResponse(render_login(_login_error(username)), status_code=200)


@router.post("/xmlrpc.php")
async def xmlrpc_post(request: Request) -> Response:
    # Vecteur WP majeur : brute-force amplifié (system.multicall) et pingback.
    body = (await request.body()).decode("utf-8", "replace")
    methods = _XMLRPC_METHOD.findall(body)
    strings = [s for s in _XMLRPC_STRING.findall(body) if not _METHOD_LIKE.match(s)]
    username = strings[0] if strings else ""
    password = strings[1] if len(strings) > 1 else ""
    classification = None
    if "system.multicall" in methods:
        classification = {
            "category": "BRUTE_FORCE",
            "severity": "high",
            "tags": ["xmlrpc_multicall"],
        }
    _emit(
        request,
        "credential_attempt",
        username,
        password,
        classification=classification,
        extra={"body": body[:4096], "xmlrpc_methods": ",".join(methods[:20])},
    )
    return Response(content=_XMLRPC_FAULT, media_type="text/xml", status_code=200)


@router.post("/admin/login", response_class=HTMLResponse)
@router.post("/phpmyadmin", response_class=HTMLResponse)
@router.post("/phpmyadmin/index.php", response_class=HTMLResponse)
async def generic_login_post(request: Request) -> HTMLResponse:
    form = dict(await request.form())
    _emit(request, "credential_attempt", _pick(form, _USER_FIELDS), _pick(form, _PASS_FIELDS))
    return HTMLResponse("<p>Access denied for this user.</p>", status_code=200)
