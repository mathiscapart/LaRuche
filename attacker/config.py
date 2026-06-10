from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

PACKAGE_ROOT: Path = Path(__file__).resolve().parent
PAYLOADS_DIR: Path = PACKAGE_ROOT / "payloads"
WORDLISTS_DIR: Path = PACKAGE_ROOT / "wordlists"
DEFAULT_REPORTS_DIR: Path = PACKAGE_ROOT / "reports"

PAYLOAD_HTTP_PATHS: Path = PAYLOADS_DIR / "http_paths.txt"
PAYLOAD_HTTP_INJECTIONS: Path = PAYLOADS_DIR / "http_injections.txt"

DEFAULT_TARGET: str = "127.0.0.1"
DEFAULT_LOG_API_URL: str = ""


def load_lines(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"Payload file not found: {path}")

    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        entry = raw.split("#", 1)[0].strip()
        if entry:
            lines.append(entry)

    return lines


def find_first_existing(candidates: tuple[Path, ...]) -> Path | None:
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return None
