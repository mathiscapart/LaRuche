"""Unit tests for attacker.deps dependency checks."""

from __future__ import annotations

from attacker import deps
from attacker.deps import (
    BinarySpec,
    CheckReport,
    DepResult,
    check_binary,
    check_for_command,
    check_payload_file,
    check_python,
)


# --- DepResult / CheckReport ----------------------------------------------
def test_depresult_ok_and_blocking():
    ok = DepResult("x", "binary", "ok")
    assert ok.ok is True
    assert ok.blocking is False

    missing_required = DepResult("y", "binary", "missing", required=True)
    assert missing_required.blocking is True

    missing_optional = DepResult("z", "binary", "missing", required=False)
    assert missing_optional.blocking is False


def test_check_report_by_kind_and_has_blocking():
    report = CheckReport()
    report.add(DepResult("a", "binary", "ok"))
    report.add(DepResult("b", "network", "unreachable", required=False))
    report.add(DepResult("c", "payload", "missing", required=True))
    assert [r.name for r in report.by_kind("binary")] == ["a"]
    assert report.has_blocking is True


# --- check_python ----------------------------------------------------------
def test_check_python_ok_for_current_interpreter():
    assert check_python().ok is True


def test_check_python_flags_too_old():
    result = check_python(min_major=99, min_minor=0)
    assert result.ok is False
    assert result.status == "wrong_version"


# --- check_binary ----------------------------------------------------------
def test_check_binary_found_on_path(monkeypatch):
    monkeypatch.setattr(deps.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(deps, "_binary_version", lambda b, v: "1.2.3")
    result = check_binary(BinarySpec("nmap", "discovery"))
    assert result.ok is True
    assert "1.2.3" in result.detail


def test_check_binary_uses_alt_path(monkeypatch, tmp_path):
    alt = tmp_path / "dirsearch.py"
    alt.write_text("#", encoding="utf-8")
    monkeypatch.setattr(deps.shutil, "which", lambda name: None)
    monkeypatch.setattr(deps, "_binary_version", lambda b, v: "")
    spec = BinarySpec("dirsearch", "discovery", required=False, alt_paths=(str(alt),))
    result = check_binary(spec)
    assert result.ok is True
    assert result.detail == str(alt)


def test_check_binary_missing(monkeypatch):
    monkeypatch.setattr(deps.shutil, "which", lambda name: None)
    result = check_binary(BinarySpec("nope", "x"))
    assert result.status == "missing"
    assert result.blocking is True


# --- check_payload_file ----------------------------------------------------
def test_check_payload_file_ok_counts_entries(tmp_path):
    f = tmp_path / "paths.txt"
    f.write_text("/a\n# comment\n\n/b\n", encoding="utf-8")
    result = check_payload_file(f, used_for="paths")
    assert result.ok is True
    assert "2 entries" in result.detail


def test_check_payload_file_missing(tmp_path):
    result = check_payload_file(tmp_path / "absent.txt", used_for="paths")
    assert result.status == "missing"


def test_check_payload_file_empty_is_missing(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("# only comments\n\n", encoding="utf-8")
    result = check_payload_file(f, used_for="paths")
    assert result.status == "missing"


# --- check_for_command -----------------------------------------------------
def test_check_for_command_ssh_only_needs_hydra(monkeypatch):
    monkeypatch.setattr(deps, "check_binary", lambda spec: DepResult(spec.name, "binary", "ok"))
    report = check_for_command("ssh", check_network=False)
    binary_names = {r.name for r in report.by_kind("binary")}
    assert binary_names == {"hydra"}


def test_check_for_command_all_dedupes_hydra(monkeypatch):
    monkeypatch.setattr(deps, "check_binary", lambda spec: DepResult(spec.name, "binary", "ok"))
    report = check_for_command("all", check_network=False)
    names = [r.name for r in report.by_kind("binary")]
    assert names.count("hydra") == 1
    assert {"nmap", "nikto", "dirsearch", "hydra"} <= set(names)


def test_check_for_command_runs_network_checks(monkeypatch):
    monkeypatch.setattr(deps, "check_binary", lambda spec: DepResult(spec.name, "binary", "ok"))
    monkeypatch.setattr(
        deps,
        "check_tcp_port",
        lambda host, port, **k: DepResult(f"{k['service']}@{port}", "network", "ok", required=False),
    )
    report = check_for_command("ssh", target="1.2.3.4", check_network=True)
    assert report.by_kind("network")
