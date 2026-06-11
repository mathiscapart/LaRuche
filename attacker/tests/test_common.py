"""Unit tests for attacker.attacks.common (no network / no real subprocess)."""

from __future__ import annotations

from unittest import mock

import pytest

from attacker.attacks import common
from attacker.attacks.common import (
    BruteforceResult,
    HttpResponse,
    ResultsDir,
    _collect_headers,
    make_results_dir,
    prompt_yes_no,
    resolve_default_credentials,
    resolve_password_wordlist,
    resolve_username_wordlist,
    run_command,
    run_credential_bruteforce,
    run_hydra,
)


# --- HttpResponse ----------------------------------------------------------
def test_http_response_header_is_case_insensitive():
    resp = HttpResponse(method="GET", path="/", status=200, headers={"server": "nginx"})
    assert resp.header("Server") == "nginx"
    assert resp.header("missing") == ""
    assert resp.ok is True


def test_http_response_ok_is_false_without_status():
    assert HttpResponse(method="GET", path="/", status=None).ok is False


def test_collect_headers_folds_duplicate_set_cookie():
    class _Msg:
        def items(self):
            return [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"), ("Server", "x")]

    collected = _collect_headers(_Msg())
    assert collected["set-cookie"] == "a=1, b=2"
    assert collected["server"] == "x"


def test_collect_headers_handles_missing_items():
    assert _collect_headers([]) == {}


# --- ResultsDir ------------------------------------------------------------
def test_results_dir_creates_files_under_prefixed_path(tmp_path):
    results = make_results_dir(tmp_path, prefix="ssh")
    assert results.path.is_dir()
    assert results.path.name.startswith("ssh-")

    target = results.file("out.txt")
    target.write_text("hi", encoding="utf-8")
    assert target.parent == results.path
    assert target.read_text(encoding="utf-8") == "hi"


# --- run_command -----------------------------------------------------------
def test_run_command_captures_stdout():
    result = run_command(["printf", "hello"])
    assert result.return_code == 0
    assert result.stdout == "hello"
    assert result.ok is True


def test_run_command_missing_binary_returns_127():
    result = run_command(["this-binary-does-not-exist-xyz"])
    assert result.return_code == 127
    assert "command not found" in result.stderr
    assert result.ok is False


def test_run_command_timeout_sets_timed_out(tmp_path):
    result = run_command(["sleep", "5"], timeout=0.05)
    assert result.timed_out is True
    assert result.return_code == 124
    assert result.ok is False


def test_run_command_writes_log_file(tmp_path):
    log = tmp_path / "cmd.log"
    run_command(["printf", "abc"], log_to=log)
    assert "abc" in log.read_text(encoding="utf-8")


# --- prompt_yes_no ---------------------------------------------------------
def test_prompt_yes_no_non_interactive_returns_default(monkeypatch):
    monkeypatch.setattr(common.sys.stdin, "isatty", lambda: False)
    assert prompt_yes_no("go?", default=False) is False
    assert prompt_yes_no("go?", default=True) is True


def test_prompt_yes_no_interactive_reads_answer(monkeypatch):
    monkeypatch.setattr(common.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    assert prompt_yes_no("go?") is True

    monkeypatch.setattr("builtins.input", lambda *_: "n")
    assert prompt_yes_no("go?", default=True) is False

    monkeypatch.setattr("builtins.input", lambda *_: "")
    assert prompt_yes_no("go?", default=True) is True


# --- resolve_* wordlists ---------------------------------------------------
def test_resolve_password_wordlist_prefers_existing_override(tmp_path):
    override = tmp_path / "pw.txt"
    override.write_text("x", encoding="utf-8")
    assert resolve_password_wordlist(override) == override


def test_resolve_password_wordlist_falls_back_to_ensure(monkeypatch, tmp_path):
    sentinel = tmp_path / "downloaded.txt"
    monkeypatch.setattr(common, "ensure_password_wordlist", lambda: sentinel)
    assert resolve_password_wordlist(None) == sentinel
    # A non-existent override is ignored in favour of the ensure() result.
    assert resolve_password_wordlist(tmp_path / "missing.txt") == sentinel


def test_resolve_username_wordlist_falls_back_to_ensure(monkeypatch, tmp_path):
    sentinel = tmp_path / "users.txt"
    monkeypatch.setattr(common, "ensure_username_wordlist", lambda: sentinel)
    assert resolve_username_wordlist(None) == sentinel


def test_resolve_default_credentials_dispatch(monkeypatch, tmp_path):
    ssh = tmp_path / "ssh.txt"
    ftp = tmp_path / "ftp.txt"
    monkeypatch.setattr(common, "ensure_ssh_default_credentials", lambda: ssh)
    monkeypatch.setattr(common, "ensure_ftp_default_credentials", lambda: ftp)
    assert resolve_default_credentials(None, "ssh") == ssh
    assert resolve_default_credentials(None, "ftp") == ftp
    assert resolve_default_credentials(None, "telnet") is None


def test_resolve_default_credentials_honours_override(tmp_path):
    override = tmp_path / "creds.txt"
    override.write_text("root:root", encoding="utf-8")
    assert resolve_default_credentials(override, "ssh") == override


# --- run_hydra (mock the subprocess) ---------------------------------------
def _fake_command_result(stdout: str):
    return common.CommandResult(
        return_code=0, stdout=stdout, stderr="", duration_s=0.1, cmd=("hydra",)
    )


def test_run_hydra_parses_credentials(monkeypatch, tmp_path):
    stdout = (
        "[ATTEMPT] target ...\n"
        "[2222][ssh] host: 10.0.0.1   login: root   password: calvin\n"
        "[2222][ssh] host: 10.0.0.1   login: admin   password: admin\n"
    )
    monkeypatch.setattr(common, "run_command", lambda *a, **k: _fake_command_result(stdout))
    results = make_results_dir(tmp_path, prefix="ssh")
    attempts, found = run_hydra(
        "ssh", "10.0.0.1", 2222, 16, 120, results, combo_wordlist=tmp_path / "c.txt"
    )
    assert attempts == 2
    assert ("root", "calvin") in found
    assert ("admin", "admin") in found


def test_run_hydra_requires_wordlists_or_combo(tmp_path):
    results = make_results_dir(tmp_path, prefix="ssh")
    with pytest.raises(ValueError):
        run_hydra("ssh", "h", 22, 1, 1, results)


def test_run_hydra_missing_binary_returns_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(
        common,
        "run_command",
        lambda *a, **k: common.CommandResult(127, "", "x", 0.0, ("hydra",)),
    )
    results = make_results_dir(tmp_path, prefix="ssh")
    attempts, found = run_hydra(
        "ssh", "h", 22, 1, 1, results, combo_wordlist=tmp_path / "c.txt"
    )
    assert (attempts, found) == (0, [])


# --- run_credential_bruteforce orchestration -------------------------------
@pytest.fixture
def results_dir(tmp_path):
    return make_results_dir(tmp_path, prefix="ssh")


def test_bruteforce_default_phase_only_when_creds_found(monkeypatch, results_dir, tmp_path):
    calls = []

    def fake_hydra(*a, **k):
        calls.append(k.get("label"))
        return 5, [("root", "calvin")]

    monkeypatch.setattr(common, "run_hydra", fake_hydra)
    outcome = run_credential_bruteforce(
        "ssh", "h", 22, tasks=4, timeout=10, results=results_dir,
        default_credentials=tmp_path / "d.txt",
        username_wordlist=tmp_path / "u.txt",
        password_wordlist=tmp_path / "p.txt",
    )
    assert outcome.found == [("root", "calvin")]
    assert outcome.phases == ["default-credentials"]
    assert calls == ["default"]  # full phase never ran


def test_bruteforce_escalates_on_confirm(monkeypatch, results_dir, tmp_path):
    def fake_hydra(*a, **k):
        if k.get("label") == "default":
            return 3, []
        return 7, [("admin", "1234")]

    monkeypatch.setattr(common, "run_hydra", fake_hydra)
    outcome = run_credential_bruteforce(
        "ssh", "h", 22, tasks=4, timeout=10, results=results_dir,
        default_credentials=tmp_path / "d.txt",
        username_wordlist=tmp_path / "u.txt",
        password_wordlist=tmp_path / "p.txt",
        confirm_escalation=lambda _q: True,
    )
    assert outcome.phases == ["default-credentials", "full-wordlist"]
    assert outcome.attempts == 10
    assert outcome.found == [("admin", "1234")]


def test_bruteforce_skips_full_when_declined(monkeypatch, results_dir, tmp_path):
    monkeypatch.setattr(common, "run_hydra", lambda *a, **k: (3, []))
    outcome = run_credential_bruteforce(
        "ssh", "h", 22, tasks=4, timeout=10, results=results_dir,
        default_credentials=tmp_path / "d.txt",
        username_wordlist=tmp_path / "u.txt",
        password_wordlist=tmp_path / "p.txt",
        confirm_escalation=lambda _q: False,
    )
    assert outcome.phases == ["default-credentials"]


def test_bruteforce_full_wordlist_skips_defaults(monkeypatch, results_dir, tmp_path):
    labels = []
    monkeypatch.setattr(
        common, "run_hydra",
        lambda *a, **k: (labels.append(k.get("label")) or (2, [])),
    )
    outcome = run_credential_bruteforce(
        "ssh", "h", 22, tasks=4, timeout=10, results=results_dir,
        default_credentials=tmp_path / "d.txt",
        username_wordlist=tmp_path / "u.txt",
        password_wordlist=tmp_path / "p.txt",
        use_full_wordlist=True,
    )
    assert labels == ["full"]
    assert outcome.phases == ["full-wordlist"]


def test_bruteforce_no_default_list_falls_back_to_full(monkeypatch, results_dir, tmp_path):
    labels = []
    monkeypatch.setattr(
        common, "run_hydra",
        lambda *a, **k: (labels.append(k.get("label")) or (2, [])),
    )
    outcome = run_credential_bruteforce(
        "ssh", "h", 22, tasks=4, timeout=10, results=results_dir,
        default_credentials=None,
        username_wordlist=tmp_path / "u.txt",
        password_wordlist=tmp_path / "p.txt",
    )
    assert labels == ["full"]
    assert outcome.phases == ["full-wordlist"]


def test_bruteforce_full_phase_aborts_without_wordlists(monkeypatch, results_dir):
    monkeypatch.setattr(common, "run_hydra", mock.Mock())
    outcome = run_credential_bruteforce(
        "ssh", "h", 22, tasks=4, timeout=10, results=results_dir,
        default_credentials=None,
        username_wordlist=None,
        password_wordlist=None,
        use_full_wordlist=True,
    )
    assert outcome == BruteforceResult()
    common.run_hydra.assert_not_called()
