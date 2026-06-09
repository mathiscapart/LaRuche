"""Tests du honeypot FTP (EPIC-1).

Le test central (``test_all_event_types_conform_to_schema``) valide chaque type
d'événement émis par le honeypot contre ``docs/event.schema.json`` : c'est la
garantie que « les logs == le schéma ». Les autres tests couvrent les comptes,
la classification de la reconnaissance, l'arborescence leurre et le profilage.

On n'importe volontairement PAS ``server`` ici : les tests ne dépendent donc
pas de pyftpdlib (seuls config / detection / events / filesystem sont testés).
"""

import json
from pathlib import Path

import pytest
from config import Credential, load_config
from detection import SessionProfiler, classify_command, is_recon
from events import build_event, normalize_ipv4
from filesystem import DECOY_TREE, decoy_dirs, materialize
from jsonschema import Draft7Validator

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "docs" / "event.schema.json"


@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(schema, format_checker=Draft7Validator.FORMAT_CHECKER)


def _validate(validator: Draft7Validator, event: dict) -> None:
    errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


# --- conformité au schéma ---------------------------------------------------
def test_all_event_types_conform_to_schema(validator: Draft7Validator) -> None:
    common = {"src_ip": "203.0.113.7", "src_port": 51234, "session_id": "sess-1"}

    events = [
        build_event(event_type="connection", payload={}, **common),
        build_event(
            event_type="auth_attempt",
            payload={"username": "anonymous", "password": "guest@", "auth_method": "password"},
            **common,
        ),
        build_event(
            event_type="auth_success",
            payload={"username": "admin", "password": "admin123", "auth_method": "password"},
            **common,
        ),
        build_event(
            event_type="command",
            payload={"command": "LIST /backup", "path": "/backup"},
            classification=classify_command("LIST", "/backup", "/"),
            **common,
        ),
        build_event(
            event_type="command",
            payload={"command": "CWD /conf", "path": "/conf"},
            classification=classify_command("CWD", "/conf", "/"),
            **common,
        ),
        build_event(
            event_type="file_download",
            payload={"filename": "database.yml", "path": "/conf/database.yml"},
            **common,
        ),
        build_event(
            event_type="disconnection",
            payload={
                "command_count": 3,
                "commands": ["PWD ", "CWD /conf", "LIST"],
                "session_fingerprint": "deadbeef",
                "duration_ms": 5200,
            },
            classification=SessionProfiler(
                commands=["PWD", "CWD /conf", "LIST"]
            ).session_classification(),
            **common,
        ),
    ]

    for event in events:
        _validate(validator, event)
        assert event["service"] == "ftp"


def test_ipv4_normalization() -> None:
    assert normalize_ipv4("::ffff:192.0.2.10") == "192.0.2.10"
    assert normalize_ipv4("::1") == "127.0.0.1"
    assert normalize_ipv4("10.0.0.5") == "10.0.0.5"


# --- comptes (faibles + root refusé) ----------------------------------------
def test_default_credentials_accepted() -> None:
    config = load_config()
    assert config.is_allowed("admin", "admin123") is True
    assert config.is_allowed("admin", "wrong") is False


def test_root_login_always_refused() -> None:
    config = load_config()
    config.allowed_credentials.append(Credential("root", "toor"))  # même listé...
    assert config.is_allowed("root", "toor") is False  # ...root reste refusé


def test_duplicate_username_keeps_first_password() -> None:
    # FTP : un seul mot de passe par compte.
    from config import _parse_credentials

    creds = _parse_credentials("ftp:first,ftp:second,backup:b")
    by_user = {c.username: c.password for c in creds}
    assert by_user["ftp"] == "first"
    assert by_user["backup"] == "b"


# --- classification de la reconnaissance ------------------------------------
def test_listing_and_navigation_are_recon() -> None:
    for cmd in ("LIST", "NLST", "MLSD", "CWD", "PWD", "CDUP"):
        assert is_recon(cmd)
        cls = classify_command(cmd)
        assert cls is not None and cls["category"] == "RECON"


def test_transfer_commands_are_not_recon() -> None:
    assert classify_command("RETR", "conf/.env") is None
    assert classify_command("STOR", "x") is None
    assert classify_command("TYPE", "I") is None  # envoyé par tout client


def test_sensitive_decoy_access_bumps_severity() -> None:
    plain = classify_command("LIST", "", "/")
    assert plain["severity"] == "low"
    sensitive = classify_command("LIST", "/conf", "/")
    assert sensitive["severity"] == "medium"
    assert "sensitive_decoy_access" in sensitive["tags"]
    # Détecté aussi via le répertoire courant.
    in_backup = classify_command("LIST", "", "/backup")
    assert in_backup["severity"] == "medium"


# --- arborescence leurre -----------------------------------------------------
def test_materialize_creates_decoy_tree(tmp_path) -> None:
    root = materialize(str(tmp_path))
    base = Path(root)
    for folder in ("backup", "conf", "exports"):
        assert (base / folder).is_dir(), f"dossier leurre manquant: {folder}"
    # Quelques fichiers d'appât attendus.
    assert (base / "conf" / "database.yml").is_file()
    assert (base / "conf" / ".env").is_file()
    assert (base / "exports" / "clients_export_2026Q1.csv").is_file()
    # Le contenu ne fuite jamais de vraies données du conteneur.
    assert "appdb_prod" in (base / "conf" / "database.yml").read_text(encoding="utf-8")


def test_materialize_is_idempotent(tmp_path) -> None:
    materialize(str(tmp_path))
    materialize(str(tmp_path))  # ne doit pas lever
    assert (Path(tmp_path) / "backup").is_dir()


def test_decoy_dirs_matches_acceptance_criteria() -> None:
    assert sorted(decoy_dirs()) == ["/backup", "/conf", "/exports"]


def test_decoy_tree_has_required_folders() -> None:
    for folder in ("backup", "conf", "exports"):
        assert isinstance(DECOY_TREE[folder], dict)


# --- profilage de session ----------------------------------------------------
def test_recon_only_session_is_scanner() -> None:
    prof = SessionProfiler()
    for i, cmd in enumerate(["LIST", "CWD /backup", "LIST", "PWD"]):
        prof.record(cmd, i * 1.5)
    assert prof.profile() == "scanner"
    assert "recon_session" in prof.session_classification()["tags"]


def test_fast_regular_non_recon_session_is_bot() -> None:
    prof = SessionProfiler()
    for i in range(6):
        prof.record(f"RETR file{i}", i * 0.05)
    assert prof.profile() == "bot"


def test_spaced_session_is_human() -> None:
    prof = SessionProfiler()
    for i, t in enumerate([0.0, 2.0, 5.5, 9.0]):
        prof.record(f"RETR file{i}", t)
    assert prof.profile() == "human"


def test_fingerprint_is_stable_and_sequence_sensitive() -> None:
    a = SessionProfiler(commands=["PWD", "LIST", "CWD /conf"])
    b = SessionProfiler(commands=["PWD", "LIST", "CWD /conf"])
    c = SessionProfiler(commands=["LIST", "PWD", "CWD /conf"])
    assert a.fingerprint() == b.fingerprint()
    assert a.fingerprint() != c.fingerprint()
