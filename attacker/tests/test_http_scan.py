"""Unit tests for the HTTP scan detection logic (no network required)."""

from __future__ import annotations

from attacker.attacks.common import HttpResponse
from attacker.attacks.web_attacks import (
    CMS_LOGIN_VECTORS,
    LoginVector,
    _build_body,
    _login_succeeded,
    _looks_like_login,
)
from attacker.attacks.web_fingerprint import (
    CMS_SIGNATURES,
    _detect_technologies,
    _score_homepage,
)


def _resp(**kwargs) -> HttpResponse:
    base = {"method": "GET", "path": "/", "status": 200}
    base.update(kwargs)
    return HttpResponse(**base)


def _signature(name: str):
    return next(sig for sig in CMS_SIGNATURES if sig.name == name)


def test_score_homepage_detects_wordpress_from_headers_and_body():
    home = _resp(
        headers={
            "link": '<http://x/wp-json/>; rel="https://api.w.org/"',
            "x-pingback": "http://x/xmlrpc.php",
        },
        body='<meta name="generator" content="WordPress 6.5.2" /> /wp-includes/foo',
    )
    score, evidence = _score_homepage(_signature("WordPress"), home)
    assert score >= 35
    assert any("generator" in line for line in evidence)


def test_score_homepage_ignores_unrelated_target():
    home = _resp(headers={"server": "gunicorn"}, body="<html>hello</html>")
    score, _ = _score_homepage(_signature("WordPress"), home)
    assert score == 0


def test_detect_technologies_from_headers_and_cookies():
    home = _resp(
        headers={
            "server": "Apache/2.4.57",
            "x-powered-by": "PHP/7.4",
            "set-cookie": "laravel_session=abc; PHPSESSID=def",
        }
    )
    techs = _detect_technologies(home)
    assert "Apache" in techs
    assert "PHP" in techs
    assert "Laravel" in techs


def test_wordpress_form_success_via_redirect_and_cookie():
    vector = CMS_LOGIN_VECTORS["WordPress"][0]
    success = _resp(
        status=302,
        headers={
            "location": "/wp-admin/",
            "set-cookie": "wordpress_logged_in_abc=admin|fake; HttpOnly",
        },
    )
    assert _login_succeeded(success, vector) is True


def test_wordpress_form_failure_marker_blocks_success():
    vector = CMS_LOGIN_VECTORS["WordPress"][0]
    failed = _resp(
        status=200,
        body='<div id="login_error">Unknown username.</div>',
    )
    assert _login_succeeded(failed, vector) is False


def test_redirect_back_to_login_is_not_success():
    vector = CMS_LOGIN_VECTORS["WordPress"][0]
    bounced = _resp(
        status=302,
        headers={"location": "/wp-login.php?loggedout=true", "set-cookie": "sid=1"},
    )
    assert _login_succeeded(bounced, vector) is False


def test_xmlrpc_success_marker_required():
    vector = CMS_LOGIN_VECTORS["WordPress"][1]
    fault = _resp(status=200, body="<fault><value>faultCode 403</value></fault>")
    accepted = _resp(status=200, body="<member><name>isAdmin</name></member>")
    assert _login_succeeded(fault, vector) is False
    assert _login_succeeded(accepted, vector) is True


def test_build_body_form_and_template():
    form_vector = LoginVector(name="t", path="/x", user_field="log", pass_field="pwd")
    body, ctype = _build_body(form_vector, "admin", "p@ss&1")
    assert ctype == "application/x-www-form-urlencoded"
    assert b"log=admin" in body
    assert b"pwd=p%40ss%261" in body

    xml_vector = CMS_LOGIN_VECTORS["WordPress"][1]
    body, ctype = _build_body(xml_vector, "admin", "secret")
    assert ctype == "text/xml"
    assert b"<string>admin</string>" in body
    assert b"<string>secret</string>" in body


def test_looks_like_login_detects_password_form():
    assert _looks_like_login(_resp(body='<input type="password" name="pwd">')) is True
    assert _looks_like_login(_resp(status=401)) is True
    assert _looks_like_login(_resp(status=200, body="<p>welcome home</p>")) is False
