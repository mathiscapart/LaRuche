"""Unit tests for attacker.wordlists (download + cache logic, no real network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from attacker import wordlists


@pytest.fixture
def patched_dirs(monkeypatch, tmp_path):
    """Point every wordlist local path at a temp directory."""
    monkeypatch.setattr(
        wordlists, "_DIRSEARCH_WORDLIST_LOCAL", tmp_path / "directories.txt"
    )
    monkeypatch.setattr(
        wordlists, "_PASSWORD_WORDLIST_LOCAL", tmp_path / "passwords.txt"
    )
    monkeypatch.setattr(
        wordlists, "_USERNAME_WORDLIST_LOCAL", tmp_path / "usernames.txt"
    )
    monkeypatch.setattr(wordlists, "_FTP_DEFAULT_CREDS_LOCAL", tmp_path / "ftp.txt")
    monkeypatch.setattr(wordlists, "_SSH_DEFAULT_CREDS_LOCAL", tmp_path / "ssh.txt")
    monkeypatch.setattr(
        wordlists, "_HTTP_DEFAULT_PASSWORDS_LOCAL", tmp_path / "http.txt"
    )
    return tmp_path


def test_download_success(monkeypatch, tmp_path):
    dest = tmp_path / "sub" / "out.txt"

    def fake_urlretrieve(url, target):
        Path(target).write_text("a\nb\n", encoding="utf-8")

    monkeypatch.setattr(wordlists.urllib.request, "urlretrieve", fake_urlretrieve)
    assert wordlists._download("http://x/list.txt", dest) is True
    assert dest.read_text(encoding="utf-8") == "a\nb\n"
    # Temp file is renamed away, not left behind.
    assert not dest.with_suffix(".tmp").exists()


def test_download_failure_cleans_up(monkeypatch, tmp_path):
    dest = tmp_path / "out.txt"

    def boom(url, target):
        Path(target).write_text("partial", encoding="utf-8")
        raise OSError("network down")

    monkeypatch.setattr(wordlists.urllib.request, "urlretrieve", boom)
    assert wordlists._download("http://x", dest) is False
    assert not dest.exists()
    assert not dest.with_suffix(".tmp").exists()


def test_ensure_returns_cached_file_without_download(patched_dirs, monkeypatch):
    cached = patched_dirs / "ssh.txt"
    cached.write_text("root:root", encoding="utf-8")

    def fail(*_a, **_k):
        raise AssertionError("should not download when cached")

    monkeypatch.setattr(wordlists, "_download", fail)
    assert wordlists.ensure_ssh_default_credentials() == cached


def test_ensure_downloads_when_missing(patched_dirs, monkeypatch):
    expected = patched_dirs / "ftp.txt"

    def fake_download(url, dest):
        dest.write_text("anonymous:anonymous", encoding="utf-8")
        return True

    monkeypatch.setattr(wordlists, "_download", fake_download)
    assert wordlists.ensure_ftp_default_credentials() == expected


def test_ensure_returns_none_on_download_failure(patched_dirs, monkeypatch):
    monkeypatch.setattr(wordlists, "_download", lambda url, dest: False)
    assert wordlists.ensure_password_wordlist() is None
