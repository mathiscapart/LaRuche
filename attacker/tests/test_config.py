"""Unit tests for attacker.config helpers."""

from __future__ import annotations

import pytest

from attacker.config import find_first_existing, load_lines


def test_load_lines_strips_comments_and_blanks(tmp_path):
    f = tmp_path / "paths.txt"
    f.write_text(
        "/admin\n"
        "# a comment\n"
        "\n"
        "/login   # trailing comment\n"
        "   /spaced   \n",
        encoding="utf-8",
    )
    assert load_lines(f) == ["/admin", "/login", "/spaced"]


def test_load_lines_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_lines(tmp_path / "nope.txt")


def test_find_first_existing_returns_first_match(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    b.write_text("x", encoding="utf-8")
    assert find_first_existing((a, b)) == b


def test_find_first_existing_none_when_absent(tmp_path):
    assert find_first_existing((tmp_path / "x", tmp_path / "y")) is None
