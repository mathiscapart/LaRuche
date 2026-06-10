from __future__ import annotations

import logging
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from attacker.config import ALLOWLIST_FILE, Allowlist, load_allowlist
from attacker.wordlists import ensure_password_wordlist, ensure_username_wordlist

logger = logging.getLogger(__name__)

__all__ = [
    "HttpResponse",
    "ResultsDir",
    "ensure_allowed",
    "http_request",
    "is_reachable",
    "make_results_dir",
    "resolve_password_wordlist",
    "resolve_username_wordlist",
    "run_command",
    "run_hydra",
]
_DEFAULT_UA = "Mozilla/5.0 (compatible; attacker/1.0; +https://m1spro.local)"


@dataclass(frozen=True)
class CommandResult:
    return_code: int
    stdout: str
    stderr: str
    duration_s: float
    cmd: tuple[str, ...]
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.return_code == 0 and not self.timed_out


def run_command(
    cmd: list[str],
    *,
    timeout: float | None = None,
    cwd: Path | None = None,
    log_to: Path | None = None,
) -> CommandResult:
    logger.debug("$ %s  (timeout=%s)", " ".join(cmd), timeout)
    start = time.monotonic()
    timed_out = False

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        return_code = completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (
            exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        )
        return_code = 124
    except FileNotFoundError:
        return CommandResult(
            return_code=127,
            stdout="",
            stderr=f"command not found: {cmd[0]}",
            duration_s=0.0,
            cmd=tuple(cmd),
        )

    duration = time.monotonic() - start
    if log_to is not None:
        log_to.parent.mkdir(parents=True, exist_ok=True)
        log_to.write_text(
            f"$ {' '.join(cmd)}\n"
            f"--- stdout ---\n{stdout}\n"
            f"--- stderr ---\n{stderr}\n"
            f"--- rc={return_code} duration={duration:.1f}s ---\n",
            encoding="utf-8",
        )

    return CommandResult(
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration,
        cmd=tuple(cmd),
        timed_out=timed_out,
    )


@dataclass(frozen=True)
class HttpResponse:
    method: str
    path: str
    status: int | None
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None


def http_request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
) -> HttpResponse:
    url = base_url.rstrip("/") + path
    full_headers: dict[str, str] = {"User-Agent": _DEFAULT_UA}
    if headers:
        full_headers.update(headers)

    request = urllib.request.Request(
        url,
        method=method,
        data=body,
        headers=full_headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return HttpResponse(method=method, path=path, status=response.status)
    except urllib.error.HTTPError as exc:
        return HttpResponse(method=method, path=path, status=exc.code)
    except urllib.error.URLError as exc:
        return HttpResponse(
            method=method,
            path=path,
            status=None,
            error=str(exc.reason),
        )
    except (TimeoutError, OSError) as exc:
        return HttpResponse(method=method, path=path, status=None, error=str(exc))


@dataclass
class ResultsDir:
    base: Path
    prefix: str
    timestamp: str = field(
        default_factory=lambda: datetime.now().strftime("%Y%m%d-%H%M%S")
    )

    @property
    def path(self) -> Path:
        return self.base / f"{self.prefix}-{self.timestamp}"

    def ensure(self) -> Path:
        self.path.mkdir(parents=True, exist_ok=True)
        return self.path

    def file(self, name: str) -> Path:
        self.ensure()
        return self.path / name


def make_results_dir(base: Path, prefix: str) -> ResultsDir:
    results = ResultsDir(base=base, prefix=prefix)
    results.ensure()
    return results


def is_reachable(host: str, port: int, *, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolve_password_wordlist(override: Path | None) -> Path | None:
    if override is not None and override.is_file():
        return override

    return ensure_password_wordlist()


def resolve_username_wordlist(override: Path | None) -> Path | None:
    if override is not None and override.is_file():
        return override

    return ensure_username_wordlist()


def run_hydra(
    protocol: str,
    host: str,
    port: int,
    tasks: int,
    timeout: int,
    username_wordlist: Path,
    password_wordlist: Path,
    results: "ResultsDir",
) -> tuple[int, int]:
    output_file = results.file("hydra-results.txt")
    output_log = results.file("hydra.log")
    cmd = [
        "hydra",
        "-L",
        str(username_wordlist),
        "-P",
        str(password_wordlist),
        "-s",
        str(port),
        "-t",
        str(tasks),
        "-f",
        "-vV",
        "-o",
        str(output_file),
        f"{protocol}://{host}",
    ]
    logger.info(
        "hydra against %s://%s:%d (users=%s, passwords=%s)",
        protocol,
        host,
        port,
        username_wordlist,
        password_wordlist,
    )

    result = run_command(cmd, timeout=timeout + 10, log_to=output_log)
    if result.return_code == 127:
        logger.error("hydra binary not found")
        return 0, 0

    tag = f"[{port}][{protocol}]"
    attempts = sum(1 for line in result.stdout.splitlines() if tag in line)
    found = sum(
        1
        for line in result.stdout.splitlines()
        if tag in line and "login:" in line and "password:" in line
    )
    logger.info(
        "hydra completed in %.1fs (%d attempts, %d credential(s) accepted)",
        result.duration_s,
        attempts,
        found,
    )
    return attempts, found


def ensure_allowed(
    target: str,
    *,
    bypass: bool = False,
    allowlist_path: Path = ALLOWLIST_FILE,
) -> bool:
    if bypass:
        logger.warning(
            "Allowlist check bypassed (--no-allowlist-check). Target: %s",
            target,
        )
        return True

    allowlist: Allowlist = load_allowlist(allowlist_path)
    if not allowlist.networks:
        logger.error(
            "Allowlist is empty or missing (%s). Refusing to attack %s.",
            allowlist.source,
            target,
        )
        return False

    if not allowlist.is_allowed(target):
        logger.error(
            "Target %s is not in the allowlist (%s). Refusing to proceed.",
            target,
            allowlist.source,
        )
        return False

    logger.debug("Target %s is allowed by %s", target, allowlist.source)
    return True
