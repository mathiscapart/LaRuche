"""Routes WordPress émulées (US-08) + réalisme anti-détection.

Calquées sur un vrai WordPress pour piéger les scanners et résister à la
détection : homepage, REST API /wp-json (+ énumération users/posts), endpoints
courants (wp-cron, readme, license, feed), faux assets statiques, et /wp-admin
accessible seulement après un login réussi. /.env (canary) est laissé à US-11.
"""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.exceptions import HTTPException as StarletteHTTPException

router = APIRouter()

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

# Utilisateurs exposés par l'API REST (vecteur de recon WordPress classique).
_FAKE_USERS = [
    {"id": 1, "name": "admin", "slug": "admin", "link": "/author/admin/"},
    {"id": 2, "name": "editor", "slug": "editor", "link": "/author/editor/"},
]

_FAKE_POSTS = [
    {
        "id": 1,
        "slug": "hello-world",
        "status": "publish",
        "title": {"rendered": "Hello world!"},
        "excerpt": {"rendered": "<p>Welcome to WordPress. This is your first post.</p>"},
    }
]

# Extensions d'assets statiques servies avec un 200 crédible (le reste -> 404 WP).
_ASSET_TYPES = {
    ".css": "text/css",
    ".js": "application/javascript",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
}

_LICENSE_TXT = """WordPress - Web publishing software

Copyright 2011-2024 by the contributors

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
"""

_README_HTML = """<!DOCTYPE html>
<html><head><title>WordPress &#8250; ReadMe</title></head>
<body>
<h1 id="logo">WordPress</h1>
<p style="text-align: center;">Semantic Personal Publishing Platform</p>
<h1>Version 6.5.2</h1>
<p>WordPress is a state-of-the-art publishing platform with a focus on aesthetics,
web standards, and usability.</p>
</body></html>
"""

_RSS_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
	<title>My Blog</title>
	<link>http://localhost/</link>
	<description>Just another WordPress site</description>
	<generator>https://wordpress.org/?v=6.5.2</generator>
	<item>
		<title>Hello world!</title>
		<link>http://localhost/?p=1</link>
		<description>Welcome to WordPress.</description>
	</item>
</channel>
</rss>
"""

_ROBOTS_TXT = """User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
"""


def _template(name: str) -> str:
    try:
        return (_TEMPLATE_DIR / name).read_text(encoding="utf-8")
    except OSError:
        return ""


def render_login(error: str = "") -> str:
    """Page de login WP, avec un éventuel encart d'erreur injecté dans le placeholder.

    Réutilisée par le POST (login raté) pour renvoyer la page complète stylée
    plutôt qu'un message nu — un vrai WordPress réaffiche le formulaire avec
    l'erreur en tête.
    """
    return _template("wp-login.html").replace("<!--LOGIN_ERROR-->", error)


@router.get("/", response_class=HTMLResponse)
async def home() -> HTMLResponse:
    return HTMLResponse(_template("home.html"))


@router.get("/wp-login.php", response_class=HTMLResponse)
async def wp_login() -> HTMLResponse:
    response = HTMLResponse(render_login())
    # Un vrai WordPress dépose ce cookie pour vérifier le support des cookies.
    response.set_cookie("wordpress_test_cookie", "WP Cookie check", path="/")
    return response


@router.get("/wp-admin")
@router.get("/wp-admin/")
async def wp_admin(request: Request) -> Response:
    # Accessible uniquement avec un cookie de session valide (post-login).
    if any(name.startswith("wordpress_logged_in") for name in request.cookies):
        return HTMLResponse(_template("wp-admin.html"))
    return RedirectResponse(url="/wp-login.php?redirect_to=%2Fwp-admin%2F", status_code=302)


@router.get("/wp-admin/admin-ajax.php")
async def admin_ajax() -> PlainTextResponse:
    # Sans action valide, WordPress renvoie "0". Cohérent avec robots.txt.
    return PlainTextResponse("0", status_code=400)


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots() -> PlainTextResponse:
    return PlainTextResponse(_ROBOTS_TXT)


@router.get("/wp-cron.php")
async def wp_cron() -> Response:
    # WordPress répond 200 avec un corps vide.
    return Response(content=b"", status_code=200)


@router.get("/readme.html", response_class=HTMLResponse)
async def readme() -> HTMLResponse:
    return HTMLResponse(_README_HTML)


@router.get("/license.txt", response_class=PlainTextResponse)
async def license_txt() -> PlainTextResponse:
    return PlainTextResponse(_LICENSE_TXT)


@router.get("/feed")
@router.get("/feed/")
async def feed() -> Response:
    return Response(content=_RSS_FEED, media_type="application/rss+xml")


@router.get("/wp-json")
@router.get("/wp-json/")
async def wp_json(request: Request) -> JSONResponse:
    base = f"http://{request.headers.get('host', 'localhost')}"
    return JSONResponse(
        {
            "name": "My Blog",
            "description": "Just another WordPress site",
            "url": base,
            "home": base,
            "gmt_offset": 0,
            "timezone_string": "",
            "namespaces": ["oembed/1.0", "wp/v2"],
            "authentication": {},
        }
    )


@router.get("/wp-json/wp/v2/users")
async def wp_users() -> JSONResponse:
    return JSONResponse(_FAKE_USERS)


@router.get("/wp-json/wp/v2/users/{user_id}")
async def wp_user(user_id: int) -> JSONResponse:
    for user in _FAKE_USERS:
        if user["id"] == user_id:
            return JSONResponse(user)
    # Erreur exacte renvoyée par un vrai WordPress pour un ID inconnu.
    return JSONResponse(
        {"code": "rest_user_invalid_id", "message": "Invalid user ID.", "data": {"status": 404}},
        status_code=404,
    )


@router.get("/wp-json/wp/v2/posts")
async def wp_posts() -> JSONResponse:
    return JSONResponse(_FAKE_POSTS)


@router.api_route("/xmlrpc.php", methods=["GET", "HEAD", "PUT", "DELETE"])
async def xmlrpc_non_post() -> PlainTextResponse:
    # WordPress renvoie ce texte exact pour toute méthode autre que POST.
    return PlainTextResponse("XML-RPC server accepts POST requests only.", status_code=405)


@router.get("/wp-content/{rest:path}")
@router.get("/wp-includes/{rest:path}")
@router.get("/wp-admin/{rest:path}")
async def static_asset(rest: str) -> Response:
    # Sert un asset crédible pour les extensions statiques connues, sinon 404 WP.
    ext = f".{rest.rsplit('.', 1)[-1].lower()}" if "." in rest else ""
    media_type = _ASSET_TYPES.get(ext)
    if media_type is None:
        raise StarletteHTTPException(status_code=404)
    body = "/* WordPress */\n" if ext in (".css", ".js") else ""
    return Response(content=body, media_type=media_type, status_code=200)
