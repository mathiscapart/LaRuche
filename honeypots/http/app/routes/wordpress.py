"""Routes WordPress émulées (US-08) : login, admin, robots, xmlrpc.

Les réponses sont calquées sur un vrai WordPress pour piéger les scanners CMS.
La route /.env (canary) est volontairement laissée à US-11.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

router = APIRouter()

_WP_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en-US">
<head>
	<meta charset="UTF-8" />
	<title>Log In &lsaquo; WordPress</title>
	<link rel="stylesheet" href="/wp-admin/css/login.min.css" media="all" />
</head>
<body class="login no-js login-action-login wp-core-ui">
<div id="login">
	<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
	<form name="loginform" id="loginform" action="/wp-login.php" method="post">
		<p><label for="user_login">Username or Email Address<br />
			<input type="text" name="log" id="user_login" class="input" value="" size="20" /></label></p>
		<p><label for="user_pass">Password<br />
			<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></label></p>
		<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In" /></p>
	</form>
</div>
</body>
</html>
"""

_ROBOTS_TXT = """User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
"""


@router.get("/wp-login.php", response_class=HTMLResponse)
async def wp_login() -> HTMLResponse:
    return HTMLResponse(_WP_LOGIN_HTML)


@router.get("/wp-admin")
@router.get("/wp-admin/")
async def wp_admin() -> RedirectResponse:
    # Comme un vrai WP : un accès non authentifié est redirigé vers le login.
    return RedirectResponse(url="/wp-login.php?redirect_to=%2Fwp-admin%2F", status_code=302)


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots() -> PlainTextResponse:
    return PlainTextResponse(_ROBOTS_TXT)


@router.api_route("/xmlrpc.php", methods=["GET", "HEAD", "PUT", "DELETE"])
async def xmlrpc_non_post() -> PlainTextResponse:
    # WordPress renvoie ce texte exact pour toute méthode autre que POST.
    return PlainTextResponse("XML-RPC server accepts POST requests only.", status_code=405)
