"""Unit tests for attacker.logging formatting and setup."""

from __future__ import annotations

import logging

from attacker.logging import ColoredFormatter, setup_logging


def _record(level=logging.INFO, msg="hello"):
    return logging.LogRecord(
        name="t", level=level, pathname=__file__, lineno=1, msg=msg, args=(), exc_info=None
    )


def test_colored_formatter_plain():
    formatted = ColoredFormatter(use_color=False).format(_record())
    assert formatted == "[INFO ] hello"


def test_colored_formatter_with_color_wraps_level():
    formatted = ColoredFormatter(use_color=True).format(_record(logging.ERROR, "boom"))
    assert "\033[" in formatted
    assert "boom" in formatted
    assert formatted.endswith("boom")


def test_colored_formatter_interpolates_args():
    record = logging.LogRecord(
        name="t", level=logging.INFO, pathname=__file__, lineno=1,
        msg="value=%d", args=(42,), exc_info=None,
    )
    assert ColoredFormatter(use_color=False).format(record) == "[INFO ] value=42"


def test_setup_logging_levels(monkeypatch):
    monkeypatch.setattr("sys.stdout.isatty", lambda: False, raising=False)

    setup_logging(verbosity=1, no_color=True)
    assert logging.getLogger().level == logging.DEBUG

    setup_logging(verbosity=0, no_color=True)
    assert logging.getLogger().level == logging.INFO

    setup_logging(verbosity=-1, no_color=True)
    assert logging.getLogger().level == logging.WARNING


def test_setup_logging_installs_single_handler(monkeypatch):
    setup_logging(verbosity=0, no_color=True)
    setup_logging(verbosity=0, no_color=True)
    handlers = logging.getLogger().handlers
    assert len(handlers) == 1
    assert isinstance(handlers[0].formatter, ColoredFormatter)
