from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

PACKAGE_ROOT: Path = Path(__file__).resolve().parent
PAYLOADS_DIR: Path = PACKAGE_ROOT / "payloads"
WORDLISTS_DIR: Path = PACKAGE_ROOT / "wordlists"
ALLOWLIST_FILE: Path = PACKAGE_ROOT / "targets.allowlist"
DEFAULT_REPORTS_DIR: Path = PACKAGE_ROOT / "reports"

PAYLOAD_HTTP_PATHS: Path = PAYLOADS_DIR / "http_paths.txt"
PAYLOAD_HTTP_INJECTIONS: Path = PAYLOADS_DIR / "http_injections.txt"

DEFAULT_TARGET: str = "127.0.0.1"
DEFAULT_LOG_API_URL: str = ""

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Allowlist:
    networks: tuple[IpNetwork, ...]
    source: Path

    def is_allowed(self, target: str) -> bool:
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            logger.debug("Target %r is not a valid IP literal", target)
            return False

        return any(address in network for network in self.networks)


def load_allowlist(path: Path = ALLOWLIST_FILE) -> Allowlist:
    if not path.is_file():
        logger.warning("Allowlist file not found: %s (no target will be allowed)", path)
        return Allowlist(networks=(), source=path)

    networks: list[IpNetwork] = []
    for lineno, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue

        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            logger.warning(
                "Invalid allowlist entry at %s:%d (%r): %s",
                path,
                lineno,
                entry,
                exc,
            )
            continue

        networks.append(network)

    return Allowlist(networks=tuple(networks), source=path)


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
