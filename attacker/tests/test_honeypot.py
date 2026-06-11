"""Unit tests for the honeypot self-detection logic (no network required)."""

from __future__ import annotations

import logging

from attacker.attacks import honeypot
from attacker.attacks.common import HttpResponse
from attacker.attacks.honeypot import (
    SUSPECT_THRESHOLD,
    HoneypotVerdict,
    _default_pairs,
    _match_signatures,
    _read_lines,
    _SSH_BANNER_SIGNATURES,
    analyze_logins,
    detect_http,
    warn_if_suspected,
)


# --- HoneypotVerdict scoring ----------------------------------------------
def test_verdict_score_is_capped_at_100():
    verdict = HoneypotVerdict(target="ssh://x")
    verdict.add("a", "x", 80)
    verdict.add("b", "y", 80)
    assert verdict.score == 100
    assert verdict.is_suspected is True


def test_verdict_below_threshold_is_not_suspected():
    verdict = HoneypotVerdict(target="ssh://x")
    verdict.add("a", "x", SUSPECT_THRESHOLD - 1)
    assert verdict.is_suspected is False


# --- list parsing ----------------------------------------------------------
def test_read_lines_keeps_hash_in_passwords(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("root:pa#ss\n\n  admin:admin  \n", encoding="utf-8")
    assert _read_lines(f) == ["root:pa#ss", "admin:admin"]


def test_read_lines_none_returns_empty():
    assert _read_lines(None) == []


def test_default_pairs_parses_user_password(tmp_path):
    f = tmp_path / "creds.txt"
    f.write_text("root:calvin\nadmin:admin\nnocolonline\n", encoding="utf-8")
    pairs = _default_pairs(f)
    assert ("root", "calvin") in pairs
    assert ("admin", "admin") in pairs
    # A line with no ':' is skipped.
    assert all(":" not in u for u, _ in pairs)
    assert len(pairs) == 2


# --- banner signatures -----------------------------------------------------
def test_match_signatures_flags_cowrie_banner():
    verdict = HoneypotVerdict(target="ssh://x")
    _match_signatures("SSH-2.0-cowrie", _SSH_BANNER_SIGNATURES, verdict, "ssh-banner")
    assert verdict.signals
    assert any(s.indicator == "ssh-banner" for s in verdict.signals)


def test_match_signatures_ignores_clean_banner():
    verdict = HoneypotVerdict(target="ssh://x")
    _match_signatures("SSH-2.0-OpenSSH_9.6", _SSH_BANNER_SIGNATURES, verdict, "ssh-banner")
    assert verdict.signals == []


# --- analyze_logins branches ----------------------------------------------
def test_analyze_logins_no_creds_is_noop():
    verdict = HoneypotVerdict(target="ssh://x")
    analyze_logins(verdict, [], protocol="ssh", indicator="ssh")
    assert verdict.signals == []


def test_analyze_logins_same_user_many_passwords_is_any_login():
    verdict = HoneypotVerdict(target="ssh://x")
    analyze_logins(
        verdict,
        [("root", "a"), ("root", "b")],
        protocol="ssh",
        indicator="ssh",
    )
    assert verdict.score >= 85
    assert verdict.is_suspected


def test_analyze_logins_many_distinct_credentials_is_any_login():
    verdict = HoneypotVerdict(target="ssh://x")
    analyze_logins(
        verdict,
        [("a", "1"), ("b", "2"), ("c", "3")],
        protocol="ssh",
        indicator="ssh",
    )
    assert verdict.score >= 85


def test_analyze_logins_single_default_stays_under_threshold(monkeypatch):
    monkeypatch.setattr(
        honeypot,
        "_default_reference",
        lambda proto: ({("root", "calvin")}, set()),
    )
    verdict = HoneypotVerdict(target="ssh://x")
    analyze_logins(verdict, [("root", "calvin")], protocol="ssh", indicator="ssh")
    assert verdict.score == 45
    assert verdict.is_suspected is False


def test_analyze_logins_two_defaults_crosses_threshold(monkeypatch):
    # Regression: two distinct default creds must trigger the honeypot warning.
    monkeypatch.setattr(
        honeypot,
        "_default_reference",
        lambda proto: ({("root", "calvin"), ("admin", "admin")}, set()),
    )
    verdict = HoneypotVerdict(target="ssh://x")
    analyze_logins(
        verdict,
        [("root", "calvin"), ("admin", "admin")],
        protocol="ssh",
        indicator="ssh",
    )
    assert verdict.score == 90
    assert verdict.is_suspected is True


def test_analyze_logins_http_uses_password_only_list(monkeypatch):
    monkeypatch.setattr(
        honeypot,
        "_default_reference",
        lambda proto: (set(), {"admin", "password"}),
    )
    verdict = HoneypotVerdict(target="http://x")
    analyze_logins(verdict, [("anyuser", "admin")], protocol="http", indicator="http")
    assert verdict.signals
    assert verdict.signals[0].weight == 45


def test_analyze_logins_non_default_hit_adds_nothing(monkeypatch):
    monkeypatch.setattr(honeypot, "_default_reference", lambda proto: (set(), set()))
    verdict = HoneypotVerdict(target="ssh://x")
    analyze_logins(verdict, [("bob", "s3cret")], protocol="ssh", indicator="ssh")
    assert verdict.signals == []


# --- detect_http catch-all -------------------------------------------------
def test_detect_http_flags_catch_all_responder(monkeypatch):
    probe = HttpResponse(method="GET", path="/x", status=200, body="A" * 500)
    monkeypatch.setattr(honeypot, "http_request", lambda *a, **k: probe)
    home = HttpResponse(method="GET", path="/", status=200, body="welcome")
    verdict = detect_http("http://x", home)
    assert any(s.indicator == "http-catch-all" for s in verdict.signals)


def test_detect_http_signature_in_body(monkeypatch):
    empty = HttpResponse(method="GET", path="/x", status=404)
    monkeypatch.setattr(honeypot, "http_request", lambda *a, **k: empty)
    home = HttpResponse(
        method="GET", path="/", status=200, body="Powered by Glastopf honeypot"
    )
    verdict = detect_http("http://x", home)
    assert any(s.indicator == "http-signature" for s in verdict.signals)


# --- warn_if_suspected -----------------------------------------------------
def test_warn_if_suspected_emits_warning(caplog):
    verdict = HoneypotVerdict(target="ssh://x")
    verdict.add("ssh-banner", "names cowrie", 90)
    with caplog.at_level(logging.WARNING):
        emitted = warn_if_suspected(verdict, logging.getLogger("t"))
    assert emitted is True
    assert "HONEYPOT WARNING" in caplog.text


def test_warn_if_suspected_quiet_below_threshold(caplog):
    verdict = HoneypotVerdict(target="ssh://x")
    verdict.add("ssh-banner", "weak", 10)
    with caplog.at_level(logging.WARNING):
        emitted = warn_if_suspected(verdict, logging.getLogger("t"))
    assert emitted is False
    assert "HONEYPOT WARNING" not in caplog.text
