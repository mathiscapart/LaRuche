"""Unit tests for attacker.attacks.web_attacks helpers (no network)."""

from __future__ import annotations

from attacker.attacks import web_attacks
from attacker.attacks.common import HttpResponse
from attacker.attacks.web_attacks import (
    CMS_LOGIN_VECTORS,
    Finding,
    LoginVector,
    _build_body,
    _enumerate_wordpress_users,
    _login_succeeded,
    _looks_like_login,
)


def _resp(**kwargs) -> HttpResponse:
    base = {"method": "GET", "path": "/", "status": 200}
    base.update(kwargs)
    return HttpResponse(**base)


# --- Finding ---------------------------------------------------------------
def test_finding_line_with_and_without_detail():
    assert Finding("high", "Title", "extra").line() == "[HIGH    ] Title — extra"
    assert Finding("low", "Title").line() == "[LOW     ] Title"


# --- _build_body -----------------------------------------------------------
def test_build_body_urlencodes_form_fields():
    vector = LoginVector(name="t", path="/x", user_field="log", pass_field="pwd")
    body, ctype = _build_body(vector, "admin", "p@ss&1")
    assert ctype == "application/x-www-form-urlencoded"
    assert b"log=admin" in body
    assert b"pwd=p%40ss%261" in body


def test_build_body_includes_extra_fields():
    vector = LoginVector(
        name="t", path="/x", user_field="u", pass_field="p", extra=(("op", "Log In"),)
    )
    body, _ = _build_body(vector, "a", "b")
    assert b"op=Log+In" in body


def test_build_body_template_substitutes_encoded_values():
    xml_vector = CMS_LOGIN_VECTORS["WordPress"][1]
    body, ctype = _build_body(xml_vector, "admin", "secret")
    assert ctype == "text/xml"
    assert b"<string>admin</string>" in body
    assert b"<string>secret</string>" in body


# --- _login_succeeded ------------------------------------------------------
def test_login_succeeded_none_response_is_false():
    vector = LoginVector(name="t", path="/x")
    assert _login_succeeded(_resp(status=None), vector) is False


def test_login_succeeded_failure_marker_wins():
    vector = LoginVector(name="t", path="/x", failure_markers=("denied",))
    assert _login_succeeded(_resp(status=200, body="access denied"), vector) is False


def test_login_succeeded_redirect_with_auth_cookie():
    vector = LoginVector(name="t", path="/x")
    resp = _resp(
        status=302,
        headers={"location": "/dashboard", "set-cookie": "session=abc"},
    )
    assert _login_succeeded(resp, vector) is True


def test_login_succeeded_redirect_back_to_login_is_false():
    vector = LoginVector(name="t", path="/x")
    resp = _resp(
        status=302,
        headers={"location": "/login?err=1", "set-cookie": "session=abc"},
    )
    assert _login_succeeded(resp, vector) is False


def test_login_succeeded_200_with_cookie_no_failure():
    vector = LoginVector(name="t", path="/x")
    resp = _resp(status=200, body="welcome", headers={"set-cookie": "auth=1"})
    assert _login_succeeded(resp, vector) is True


def test_login_succeeded_200_with_failure_text_is_false():
    vector = LoginVector(name="t", path="/x")
    resp = _resp(status=200, body="login failed", headers={"set-cookie": "auth=1"})
    assert _login_succeeded(resp, vector) is False


# --- _looks_like_login -----------------------------------------------------
def test_looks_like_login_status_and_form():
    assert _looks_like_login(_resp(status=401)) is True
    assert _looks_like_login(_resp(status=403)) is True
    assert _looks_like_login(_resp(body='<input type="password" name="pwd">')) is True
    assert _looks_like_login(_resp(body="<p>hello</p>")) is False


# --- _enumerate_wordpress_users -------------------------------------------
def test_enumerate_wordpress_users_parses_slugs(monkeypatch):
    body = '[{"slug": "admin", "name": "Admin"}, {"name": "editor"}, {"slug": "admin"}]'
    monkeypatch.setattr(
        web_attacks, "http_request", lambda *a, **k: _resp(status=200, body=body)
    )
    users = _enumerate_wordpress_users("http://x", timeout=1.0)
    assert users == ["admin", "editor"]


def test_enumerate_wordpress_users_non_200_returns_empty(monkeypatch):
    monkeypatch.setattr(
        web_attacks, "http_request", lambda *a, **k: _resp(status=403, body="")
    )
    assert _enumerate_wordpress_users("http://x", timeout=1.0) == []


def test_enumerate_wordpress_users_bad_json_returns_empty(monkeypatch):
    monkeypatch.setattr(
        web_attacks, "http_request", lambda *a, **k: _resp(status=200, body="not json")
    )
    assert _enumerate_wordpress_users("http://x", timeout=1.0) == []
