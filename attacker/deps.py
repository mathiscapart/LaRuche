from __future__ import annotations

import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from attacker.config import (
    PAYLOAD_HTTP_INJECTIONS,
    PAYLOAD_HTTP_PATHS,
)

DepKind = Literal["python", "binary", "payload", "wordlist", "network"]
DepStatus = Literal["ok", "missing", "wrong_version", "unreachable"]
Command = Literal["check", "http", "ftp", "ssh", "all"]


@dataclass(frozen=True)
class DepResult:
    name: str
    kind: DepKind
    status: DepStatus
    detail: str = ""
    required: bool = True
    install_hint: str = ""
    used_for: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def blocking(self) -> bool:
        return not self.ok and self.required


@dataclass
class CheckReport:
    results: list[DepResult] = field(default_factory=list)

    def add(self, result: DepResult) -> None:
        self.results.append(result)

    def by_kind(self, kind: DepKind) -> list[DepResult]:
        return [r for r in self.results if r.kind == kind]

    @property
    def has_blocking(self) -> bool:
        return any(r.blocking for r in self.results)


@dataclass(frozen=True)
class BinarySpec:
    name: str
    used_for: str
    required: bool = True
    version_arg: str = "--version"
    alt_paths: tuple[str, ...] = ()


_BINARIES_HTTP: tuple[BinarySpec, ...] = (
    BinarySpec(
        "nikto",
        "HTTP vulnerability scan",
        version_arg="-Version",
    ),
    BinarySpec(
        "dirsearch",
        "directory discovery",
        required=False,
        alt_paths=("/usr/share/dirsearch/dirsearch.py", "/opt/dirsearch/dirsearch.py"),
    ),
)
_BINARIES_FTP: tuple[BinarySpec, ...] = (BinarySpec("hydra", "FTP brute-force driver"),)
_BINARIES_SSH: tuple[BinarySpec, ...] = (BinarySpec("hydra", "SSH brute-force driver"),)


def check_python(min_major: int = 3, min_minor: int = 10) -> DepResult:
    v = sys.version_info
    detail = f"{v.major}.{v.minor}.{v.micro}"
    if (v.major, v.minor) >= (min_major, min_minor):
        return DepResult(
            "python",
            "python",
            "ok",
            detail=detail,
            used_for="package runtime",
        )

    return DepResult(
        "python",
        "python",
        "wrong_version",
        detail=f"{detail} < {min_major}.{min_minor}",
        install_hint=f"Install Python {min_major}.{min_minor} or newer",
        used_for="package runtime",
    )


def _binary_version(binary: str, version_arg: str) -> str:
    try:
        proc = subprocess.run(
            [binary, version_arg],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return ""

    output = (proc.stdout + "\n" + proc.stderr).strip().splitlines()
    return output[0][:80] if output else ""


def check_binary(spec: BinarySpec) -> DepResult:
    path: str | None = shutil.which(spec.name)
    if not path:
        for alt in spec.alt_paths:
            if Path(alt).exists():
                path = alt
                break

    if not path:
        return DepResult(
            spec.name,
            "binary",
            "missing",
            detail="not found in $PATH",
            required=spec.required,
            install_hint=f"install pkg '{spec.name}'",
            used_for=spec.used_for,
        )

    version = _binary_version(spec.name, spec.version_arg)
    detail = f"{path}  ({version})" if version else path
    return DepResult(
        spec.name,
        "binary",
        "ok",
        detail=detail,
        required=spec.required,
        used_for=spec.used_for,
    )


def check_payload_file(path: Path, *, used_for: str) -> DepResult:
    name = path.name
    if not path.is_file():
        return DepResult(
            name,
            "payload",
            "missing",
            detail=f"missing file: {path}",
            install_hint="restore the file from the repository",
            used_for=used_for,
        )
    text = path.read_text(encoding="utf-8", errors="replace")
    line_count = sum(1 for raw in text.splitlines() if raw.split("#", 1)[0].strip())
    if line_count == 0:
        return DepResult(
            name,
            "payload",
            "missing",
            detail=f"{path} is empty",
            install_hint="restore the file from the repository",
            used_for=used_for,
        )

    return DepResult(
        name,
        "payload",
        "ok",
        detail=f"{path}  ({line_count} entries)",
        used_for=used_for,
    )


def check_tcp_port(
    host: str,
    port: int,
    *,
    service: str,
    timeout: float = 5.0,
) -> DepResult:
    label = f"{service} @ {host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return DepResult(
                label,
                "network",
                "ok",
                detail=f"connected in <{timeout}s",
                required=False,
                used_for=f"{service} target",
            )
    except OSError as exc:
        return DepResult(
            label,
            "network",
            "unreachable",
            detail=f"{type(exc).__name__}: {exc}",
            required=False,
            install_hint=(
                f"Start the {service} honeypot container "
                f"and check firewall rules for port {port}"
            ),
            used_for=f"{service} target",
        )


def check_for_command(
    command: Command,
    *,
    target: str = "",
    ports: dict[str, int] | None = None,
    check_network: bool = True,
) -> CheckReport:
    report = CheckReport()
    ports = ports or {}

    report.add(check_python())

    binaries: list[BinarySpec] = []
    if command in ("http", "all", "check"):
        binaries.extend(_BINARIES_HTTP)

    if command in ("ftp", "all", "check"):
        binaries.extend(_BINARIES_FTP)

    if command in ("ssh", "all", "check"):
        binaries.extend(_BINARIES_SSH)

    seen: set[str] = set()
    for spec in binaries:
        if spec.name in seen:
            continue
        seen.add(spec.name)
        report.add(check_binary(spec))

    if command in ("http", "all", "check"):
        report.add(check_payload_file(PAYLOAD_HTTP_PATHS, used_for="HTTP probe paths"))
        report.add(
            check_payload_file(
                PAYLOAD_HTTP_INJECTIONS,
                used_for="HTTP injection probes",
            )
        )

    if check_network and target:
        if command in ("http", "all", "check"):
            report.add(
                check_tcp_port(
                    target,
                    ports.get("http", 80),
                    service="http",
                ),
            )

        if command in ("ftp", "all", "check"):
            report.add(
                check_tcp_port(
                    target,
                    ports.get("ftp", 21),
                    service="ftp",
                ),
            )

        if command in ("ssh", "all", "check"):
            report.add(
                check_tcp_port(
                    target,
                    ports.get("ssh", 2222),
                    service="ssh",
                ),
            )

    return report
