from __future__ import annotations

import logging
import os
import sys

_ANSI = {
    "DEBUG": "\033[0;90m",
    "INFO": "\033[0;36m",
    "PASS": "\033[0;32m",
    "WARNING": "\033[1;33m",
    "FAIL": "\033[0;31m",
    "ERROR": "\033[0;31m",
    "CRITICAL": "\033[1;31m",
    "RESET": "\033[0m",
}


class ColoredFormatter(logging.Formatter):
    def __init__(self, use_color: bool) -> None:
        super().__init__()
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        message = record.getMessage()
        if self._use_color:
            color = _ANSI.get(level, "")
            reset = _ANSI["RESET"]
            return f"{color}[{level:<5}]{reset} {message}"

        return f"[{level:<5}] {message}"


def setup_logging(verbosity: int, no_color: bool) -> None:
    if verbosity >= 1:
        level = logging.DEBUG
    elif verbosity < 0:
        level = logging.WARNING
    else:
        level = logging.INFO

    use_color = not (no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty())
    root = logging.getLogger()
    root.setLevel(level)

    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter(use_color=use_color))
    handler.setLevel(level)
    root.addHandler(handler)
