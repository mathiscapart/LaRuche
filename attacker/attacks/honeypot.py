"""Honeypot self-detection — *"am I about to attack a trap?"*

The toolkit's job is to validate honeypots, so the operator usually *knows* the
target is one. But when these scripts are pointed at an unknown host it is worth
warning loudly when the target itself looks like a honeypot / decoy: a real
attacker who keeps hammering an instrumented system just feeds it telemetry.

Detection is woven *into* the attack rather than run beside it, so it costs no
extra brute-force pass:

  * **Banner / body signatures** (passive) — known honeypot defaults (Cowrie,
    Kippo, Dionaea, Glastopf, Conpot, ...) plus a single catch-all HTTP probe.
  * **Credential analysis** — :func:`analyze_logins` takes the credentials the
    *real* brute-force already cracked and reads their shape:
      - one user accepted with several passwords, or an implausibly large haul
        → the service logs anyone in, every hit is a decoy;
      - the cracked pairs are the service's *known default* credentials (looked
        up in the SecLists lists) → classic out-of-the-box honeypot behaviour.

So the default-credential check reuses the attack's output instead of replaying
its own logins. Each check contributes a weighted :class:`HoneypotSignal`; the
weights are summed (capped at 100). Above :data:`SUSPECT_THRESHOLD` the caller
emits a warning — we never *block* an attack, we only flag it.
"""

from __future__ import annotations

import logging
import re
import secrets
import socket
from dataclasses import dataclass, field
from pathlib import Path

from attacker.attacks.common import HttpResponse, http_request
from attacker.wordlists import (
    ensure_ftp_default_credentials,
    ensure_http_default_passwords,
    ensure_ssh_default_credentials,
)

logger = logging.getLogger(__name__)

__all__ = [
    "HoneypotSignal",
    "HoneypotVerdict",
    "SUSPECT_THRESHOLD",
    "analyze_logins",
    "detect_ftp",
    "detect_http",
    "detect_ssh",
    "warn_if_suspected",
]

# Confidence (0-100) at or above which we treat the target as a likely honeypot.
SUSPECT_THRESHOLD = 50

# Shared weights so every protocol agrees on how damning each observation is.
_WEIGHT_ANY_LOGIN = 85  # accepts anyone -> brute-force "successes" are fake
_WEIGHT_DEFAULT_LOGIN = 45  # cracked creds are known service defaults

# A real service yields ~1 valid pair; this many distinct hits means it accepts
# (almost) anything — i.e. the brute-force "successes" are honeypot decoys.
_MANY_CREDENTIALS = 3


@dataclass(frozen=True)
class HoneypotSignal:
    """A single piece of evidence that the target may be a honeypot."""

    indicator: str  # short label, e.g. "ssh-banner"
    detail: str  # human-readable evidence
    weight: int  # 0-100 confidence contribution


@dataclass
class HoneypotVerdict:
    target: str
    signals: list[HoneypotSignal] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(sum(s.weight for s in self.signals), 100)

    @property
    def is_suspected(self) -> bool:
        return self.score >= SUSPECT_THRESHOLD

    def add(self, indicator: str, detail: str, weight: int) -> None:
        self.signals.append(HoneypotSignal(indicator, detail, weight))


# --- Banner / body signature database -------------------------------------
# (regex, label, weight). Matched case-insensitively. These are heuristics:
# known honeypot defaults and tell-tale strings.
_SSH_BANNER_SIGNATURES: tuple[tuple[str, str, int], ...] = (
    # Cowrie/Kippo ship these exact OpenSSH version strings by default.
    (r"OpenSSH_6\.0p1 Debian-4\+deb7u2", "Cowrie default SSH banner", 80),
    (r"OpenSSH_5\.1p1 Debian-5", "Kippo default SSH banner", 80),
    (r"cowrie", "banner names Cowrie", 90),
    (r"kippo", "banner names Kippo", 90),
    (r"honey", "banner contains 'honey'", 60),
)
_FTP_BANNER_SIGNATURES: tuple[tuple[str, str, int], ...] = (
    (r"Welcome to the ftp service", "Dionaea default FTP banner", 70),
    (r"dionaea", "banner names Dionaea", 90),
    (r"honey", "banner contains 'honey'", 60),
    # Dionaea historically spoofed a Microsoft FTP banner verbatim.
    (r"Microsoft FTP Service", "spoofed Microsoft FTP banner", 30),
)
_HTTP_SIGNATURES: tuple[tuple[str, str, int], ...] = (
    (r"glastopf", "Glastopf honeypot fingerprint", 90),
    (r"\bsnare\b|tanner", "SNARE/Tanner honeypot fingerprint", 85),
    (r"conpot", "Conpot honeypot fingerprint", 90),
    (r"honeypot|honeytrap|honeypy", "page mentions honeypot", 70),
)


def _match_signatures(
    text: str,
    signatures: tuple[tuple[str, str, int], ...],
    verdict: HoneypotVerdict,
    indicator: str,
) -> None:
    for pattern, label, weight in signatures:
        if re.search(pattern, text, re.IGNORECASE):
            verdict.add(indicator, label, weight)


def _grab_tcp_banner(host: str, port: int, *, timeout: float) -> str:
    """Read the greeting an SSH/FTP server pushes on connect (best effort)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return sock.recv(512).decode("utf-8", "replace").strip()
    except OSError as exc:
        logger.debug("banner grab failed for %s:%d (%s)", host, port, exc)
        return ""


# --- Default-credential reference lists (SecLists) -------------------------
def _read_lines(path: Path | None) -> list[str]:
    """Read a credential list without stripping ``#`` — SecLists passwords may
    legitimately contain it, so the project's ``load_lines`` is unsafe here."""
    if path is None:
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip()]


def _default_pairs(path: Path | None) -> set[tuple[str, str]]:
    """Parse ``user:password`` pairs (ftp/ssh SecLists format)."""
    pairs: set[tuple[str, str]] = set()
    for line in _read_lines(path):
        user, sep, password = line.partition(":")
        if sep:
            pairs.add((user, password))

    return pairs


def _default_reference(protocol: str) -> tuple[set[tuple[str, str]], set[str]]:
    """Return ``(default_pairs, default_passwords)`` for a protocol.

    ssh/ftp ship full ``user:password`` pairs; the http list is password-only,
    so a cracked pair counts as "default" when its password is in that list.
    """
    if protocol == "ssh":
        return _default_pairs(ensure_ssh_default_credentials()), set()
    if protocol == "ftp":
        return _default_pairs(ensure_ftp_default_credentials()), set()
    if protocol == "http":
        return set(), set(_read_lines(ensure_http_default_passwords()))
    return set(), set()


def analyze_logins(
    verdict: HoneypotVerdict,
    found_credentials: list[tuple[str, str]],
    *,
    protocol: str,
    indicator: str,
) -> None:
    """Fold the *full* brute-force result back into the verdict.

    This is the coherence link between phases: rather than trust the cracked
    credentials, we read their shape. A single user accepted with several
    passwords or an implausibly large haul both mean the host logs anyone in;
    failing that, we check whether the few hits are the service's *known
    defaults* — which is what an out-of-the-box honeypot hands out.
    """
    distinct = set(found_credentials)
    if not distinct:
        return

    passwords_per_user: dict[str, set[str]] = {}
    for user, password in distinct:
        passwords_per_user.setdefault(user, set()).add(password)

    multi = max(passwords_per_user.items(), key=lambda item: len(item[1]))
    if len(multi[1]) >= 2:
        verdict.add(
            indicator,
            f"user '{multi[0]}' authenticated with {len(multi[1])} different "
            "passwords — the service accepts any password, the hits are decoys",
            _WEIGHT_ANY_LOGIN,
        )
        return

    if len(distinct) >= _MANY_CREDENTIALS:
        verdict.add(
            indicator,
            f"brute-force accepted {len(distinct)} distinct credentials "
            "(a hardened service accepts ~1) — likely a credential-harvesting trap",
            _WEIGHT_ANY_LOGIN,
        )
        return

    # Only a couple of hits: are they the service's well-known default creds?
    default_pairs, default_passwords = _default_reference(protocol)
    defaults_hit = sorted(
        (user, password)
        for user, password in distinct
        if (user, password) in default_pairs or password in default_passwords
    )

    if defaults_hit:
        shown = ", ".join(f"{u}:{p}" for u, p in defaults_hit[:5])
        verdict.add(
            indicator,
            f"cracked credential(s) are known {protocol} service defaults: {shown}",
            _WEIGHT_DEFAULT_LOGIN,
        )


# --- Public detectors (passive — no logins of their own) -------------------
def detect_ssh(host: str, port: int, *, timeout: float = 5.0) -> HoneypotVerdict:
    verdict = HoneypotVerdict(target=f"ssh://{host}:{port}")
    banner = _grab_tcp_banner(host, port, timeout=timeout)
    if banner:
        logger.debug("SSH banner: %s", banner)
        _match_signatures(banner, _SSH_BANNER_SIGNATURES, verdict, "ssh-banner")
    return verdict


def detect_ftp(host: str, port: int, *, timeout: float = 5.0) -> HoneypotVerdict:
    verdict = HoneypotVerdict(target=f"ftp://{host}:{port}")
    banner = _grab_tcp_banner(host, port, timeout=timeout)
    if banner:
        logger.debug("FTP banner: %s", banner)
        _match_signatures(banner, _FTP_BANNER_SIGNATURES, verdict, "ftp-banner")

    return verdict


# A path no real site serves; a catch-all honeypot answers it with 200 + body.
_DECOY_PATH_PREFIX = "/zzz-honeypot-probe-"


def detect_http(
    base_url: str,
    home: HttpResponse,
    *,
    timeout: float = 10.0,
) -> HoneypotVerdict:
    verdict = HoneypotVerdict(target=base_url)

    haystack = " ".join(
        (
            home.header("server"),
            home.header("x-powered-by"),
            home.header("set-cookie"),
            home.body[:8000],
        )
    )
    _match_signatures(haystack, _HTTP_SIGNATURES, verdict, "http-signature")

    decoy_path = f"{_DECOY_PATH_PREFIX}{secrets.token_hex(8)}"
    probe = http_request(base_url, decoy_path, timeout=timeout, capture_body=True)
    if probe.status == 200 and len(probe.body.strip()) > 200:
        verdict.add(
            "http-catch-all",
            f"random path {decoy_path} returned 200 with content "
            "(catch-all responders are typical of web honeypots)",
            45,
        )

    return verdict


def warn_if_suspected(verdict: HoneypotVerdict, log: logging.Logger) -> bool:
    """Emit a prominent warning when the target looks like a honeypot.

    Returns ``True`` if a warning was emitted, so callers can record it.
    """
    if not verdict.is_suspected:
        if verdict.signals:
            log.debug(
                "Honeypot heuristics below threshold for %s (score=%d)",
                verdict.target,
                verdict.score,
            )
        return False

    log.warning("=" * 64)
    log.warning(
        "HONEYPOT WARNING: %s looks like a honeypot / trap (confidence %d%%)",
        verdict.target,
        verdict.score,
    )

    for signal in verdict.signals:
        log.warning("  - [%s] %s (+%d)", signal.indicator, signal.detail, signal.weight)

    log.warning("Continuing, but this target is likely instrumented and logging you.")
    log.warning("=" * 64)
    return True
