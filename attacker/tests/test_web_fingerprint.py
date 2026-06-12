"""Unit tests for attacker.attacks.web_fingerprint (homepage + markers)."""

from __future__ import annotations

from attacker.attacks import web_fingerprint
from attacker.attacks.common import HttpResponse
from attacker.attacks.web_fingerprint import (
    CMS_SIGNATURES,
    _detect_technologies,
    _detect_version,
    _score_homepage,
    fingerprint,
)


def _resp(**kwargs) -> HttpResponse:
    base = {"method": "GET", "path": "/", "status": 200}
    base.update(kwargs)
    return HttpResponse(**base)


def _signature(name: str):
    return next(sig for sig in CMS_SIGNATURES if sig.name == name)


# --- _score_homepage -------------------------------------------------------
def test_score_homepage_wordpress_signals():
    home = _resp(
        headers={"x-pingback": "http://x/xmlrpc.php"},
        body='<meta name="generator" content="WordPress 6.5" /> /wp-includes/x',
    )
    score, evidence = _score_homepage(_signature("WordPress"), home)
    assert score >= 35
    assert evidence


def test_score_homepage_no_match_is_zero():
    score, evidence = _score_homepage(_signature("Drupal"), _resp(body="plain"))
    assert score == 0
    assert evidence == []


# --- _detect_technologies --------------------------------------------------
def test_detect_technologies_dedupes_php():
    home = _resp(
        headers={
            "server": "Apache",
            "x-powered-by": "PHP/8.1",
            "set-cookie": "PHPSESSID=abc",
        },
        body="/wp-content/themes/x",
    )
    techs = _detect_technologies(home)
    assert "Apache" in techs
    assert techs.count("PHP") == 1


def test_detect_technologies_empty_for_bare_response():
    assert _detect_technologies(_resp(body="<html></html>")) == []


# --- _detect_version -------------------------------------------------------
def test_detect_version_from_inline_generator(monkeypatch):
    home = _resp(body='<meta name="generator" content="WordPress 6.5.2" />')
    # No network needed: the inline generator short-circuits before version_paths.
    version = _detect_version(
        _signature("WordPress"), "http://x", home, timeout=1, pause=0
    )
    assert version == "6.5.2"


def test_detect_version_from_version_path(monkeypatch):
    home = _resp(body="no generator here")
    monkeypatch.setattr(
        web_fingerprint,
        "http_request",
        lambda *a, **k: _resp(status=200, body="Version 4.9.1"),
    )
    version = _detect_version(
        _signature("WordPress"), "http://x", home, timeout=1, pause=0
    )
    assert version == "4.9.1"


# --- fingerprint (full flow with mocked markers) ---------------------------
def test_fingerprint_identifies_wordpress(monkeypatch):
    home = _resp(
        headers={"server": "Apache", "x-pingback": "http://x/xmlrpc.php"},
        body='<meta name="generator" content="WordPress 6.5.2" /> /wp-includes/',
    )
    # Marker + version requests all answer positively.
    monkeypatch.setattr(
        web_fingerprint,
        "http_request",
        lambda *a, **k: _resp(status=200, body="loginform user_login"),
    )
    fp = fingerprint("http://x", home=home, pause=0)
    assert fp.cms == "WordPress"
    assert fp.is_cms is True
    assert fp.attackable_cms is True
    assert fp.cms_version == "6.5.2"


def test_fingerprint_hosted_platform_not_attackable(monkeypatch):
    home = _resp(headers={"x-shopid": "123"}, body="cdn.shopify.com/x")
    monkeypatch.setattr(
        web_fingerprint, "http_request", lambda *a, **k: _resp(status=404)
    )
    fp = fingerprint("http://x", home=home, pause=0)
    assert fp.cms == "Shopify"
    assert fp.hosted is True
    assert fp.attackable_cms is False


def test_fingerprint_unknown_target(monkeypatch):
    home = _resp(headers={"server": "nginx"}, body="<html>plain</html>")
    monkeypatch.setattr(
        web_fingerprint, "http_request", lambda *a, **k: _resp(status=404)
    )
    fp = fingerprint("http://x", home=home, pause=0)
    assert fp.is_cms is False
    assert fp.server == "nginx"
