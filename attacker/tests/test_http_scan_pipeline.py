"""Unit tests for attacker.attacks.http_scan parsing/config helpers (no network)."""

from __future__ import annotations

import json

from attacker.attacks import http_scan
from attacker.attacks.http_scan import (
    HttpScanConfig,
    _build_credentials,
    _parse_dirsearch_json,
    _parse_nikto_csv,
)


# --- HttpScanConfig.base_url ----------------------------------------------
def test_base_url_scheme_and_port():
    assert HttpScanConfig("h", 80).base_url == "http://h"
    assert HttpScanConfig("h", 443).base_url == "https://h"
    assert HttpScanConfig("h", 8080).base_url == "http://h:8080"


# --- _parse_nikto_csv ------------------------------------------------------
def test_parse_nikto_csv_filters_by_host(tmp_path):
    csv_file = tmp_path / "nikto"
    csv_file.write_text(
        '"target","1.2.3.4","80","0","GET","/admin","Admin found"\n'
        '"other","9.9.9.9","80","0","GET","/x","Ignored"\n'
        '"target","1.2.3.4","80","0","GET","/y",""\n',
        encoding="utf-8",
    )
    findings = _parse_nikto_csv(csv_file, "target")
    assert len(findings) == 1
    assert "Admin found" in findings[0].title
    assert findings[0].detail == "/admin"


def test_parse_nikto_csv_missing_file(tmp_path):
    assert _parse_nikto_csv(tmp_path / "absent", "target") == []


# --- _parse_dirsearch_json -------------------------------------------------
def test_parse_dirsearch_json_extracts_interesting_paths(tmp_path):
    report = tmp_path / "dirsearch.json"
    report.write_text(
        json.dumps(
            {
                "results": [
                    {"status": 200, "path": "/admin"},
                    {"status": 404, "path": "/missing"},
                    {"status": 301, "url": "http://h/redir"},
                    {"status": 200, "path": "/"},
                    {"status": 403, "path": "/secret"},
                ]
            }
        ),
        encoding="utf-8",
    )
    paths = _parse_dirsearch_json(report)
    assert "/admin" in paths
    assert "/redir" in paths
    assert "/secret" in paths
    assert "/missing" not in paths  # 404 filtered
    assert "/" not in paths  # root filtered


def test_parse_dirsearch_json_bad_json(tmp_path):
    report = tmp_path / "dirsearch.json"
    report.write_text("not json", encoding="utf-8")
    assert _parse_dirsearch_json(report) == []


def test_parse_dirsearch_json_missing_file(tmp_path):
    assert _parse_dirsearch_json(tmp_path / "absent.json") == []


# --- _build_credentials ----------------------------------------------------
def test_build_credentials_caps_at_max_attempts(monkeypatch, tmp_path):
    users = tmp_path / "u.txt"
    users.write_text("admin\nroot\n", encoding="utf-8")
    passwords = tmp_path / "p.txt"
    passwords.write_text("a\nb\nc\n", encoding="utf-8")
    monkeypatch.setattr(http_scan, "resolve_username_wordlist", lambda o: users)
    monkeypatch.setattr(http_scan, "resolve_password_wordlist", lambda o: passwords)

    config = HttpScanConfig("h", 80, max_login_attempts=4)
    creds = _build_credentials(config)
    assert len(creds) == 4
    assert creds[0] == ("admin", "a")


def test_build_credentials_empty_when_no_wordlist(monkeypatch):
    monkeypatch.setattr(http_scan, "resolve_username_wordlist", lambda o: None)
    monkeypatch.setattr(http_scan, "resolve_password_wordlist", lambda o: None)
    assert _build_credentials(HttpScanConfig("h", 80)) == []
