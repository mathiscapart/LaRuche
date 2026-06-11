from __future__ import annotations

import logging
import urllib.request
from pathlib import Path

from attacker.config import WORDLISTS_DIR

logger = logging.getLogger(__name__)

# common.txt lists directories *and* files, so dirsearch can discover sensitive
# files (configs, backups) once paired with -e extensions — raft-medium-
# directories only ever finds directories — while staying within the scan's
# time budget (~4.7k entries vs. 30k+).
_DIRSEARCH_WORDLIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Discovery/Web-Content/common.txt"
)

_PASSWORD_WORDLIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Passwords/Common-Credentials/Pwdb_top-10000.txt"
)

_USERNAME_WORDLIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Usernames/top-usernames-shortlist.txt"
)

# Default-credential lists used by the honeypot self-detection probes. The
# ftp/ssh lists are "user:password" pairs; the http list is password-only.
_FTP_DEFAULT_CREDS_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt"
)
_SSH_DEFAULT_CREDS_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt"
)
_HTTP_DEFAULT_PASSWORDS_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Passwords/Default-Credentials/default-passwords.txt"
)

_DIRSEARCH_WORDLIST_LOCAL: Path = WORDLISTS_DIR / "directories.txt"
_PASSWORD_WORDLIST_LOCAL: Path = WORDLISTS_DIR / "passwords.txt"
_USERNAME_WORDLIST_LOCAL: Path = WORDLISTS_DIR / "usernames.txt"
_FTP_DEFAULT_CREDS_LOCAL: Path = WORDLISTS_DIR / "ftp-default-credentials.txt"
_SSH_DEFAULT_CREDS_LOCAL: Path = WORDLISTS_DIR / "ssh-default-credentials.txt"
_HTTP_DEFAULT_PASSWORDS_LOCAL: Path = WORDLISTS_DIR / "http-default-passwords.txt"


def _download(url: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    try:
        logger.info("Downloading %s ...", url)
        urllib.request.urlretrieve(url, tmp)  # noqa: S310
        tmp.replace(dest)
        line_count = sum(1 for _ in dest.open("rb"))
        logger.info("Saved %s (%d lines)", dest, line_count)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("Download failed (%s): %s", url, exc)
        tmp.unlink(missing_ok=True)
        return False


def ensure_dirsearch_wordlist() -> Path | None:
    if _DIRSEARCH_WORDLIST_LOCAL.is_file():
        return _DIRSEARCH_WORDLIST_LOCAL

    logger.info("No dirsearch wordlist found — fetching common.txt from SecLists")
    if _download(_DIRSEARCH_WORDLIST_URL, _DIRSEARCH_WORDLIST_LOCAL):
        return _DIRSEARCH_WORDLIST_LOCAL

    return None


def ensure_password_wordlist() -> Path | None:
    if _PASSWORD_WORDLIST_LOCAL.is_file():
        return _PASSWORD_WORDLIST_LOCAL

    logger.info(
        "No password wordlist found — fetching 10k common passwords from SecLists"
    )
    if _download(_PASSWORD_WORDLIST_URL, _PASSWORD_WORDLIST_LOCAL):
        return _PASSWORD_WORDLIST_LOCAL

    return None


def ensure_username_wordlist() -> Path | None:
    if _USERNAME_WORDLIST_LOCAL.is_file():
        return _USERNAME_WORDLIST_LOCAL

    logger.info(
        "No username wordlist found — fetching top usernames shortlist from SecLists"
    )
    if _download(_USERNAME_WORDLIST_URL, _USERNAME_WORDLIST_LOCAL):
        return _USERNAME_WORDLIST_LOCAL

    return None


def ensure_ftp_default_credentials() -> Path | None:
    if _FTP_DEFAULT_CREDS_LOCAL.is_file():
        return _FTP_DEFAULT_CREDS_LOCAL

    logger.info("No FTP default-credential list found — fetching from SecLists")
    if _download(_FTP_DEFAULT_CREDS_URL, _FTP_DEFAULT_CREDS_LOCAL):
        return _FTP_DEFAULT_CREDS_LOCAL

    return None


def ensure_ssh_default_credentials() -> Path | None:
    if _SSH_DEFAULT_CREDS_LOCAL.is_file():
        return _SSH_DEFAULT_CREDS_LOCAL

    logger.info("No SSH default-credential list found — fetching from SecLists")
    if _download(_SSH_DEFAULT_CREDS_URL, _SSH_DEFAULT_CREDS_LOCAL):
        return _SSH_DEFAULT_CREDS_LOCAL

    return None


def ensure_http_default_passwords() -> Path | None:
    if _HTTP_DEFAULT_PASSWORDS_LOCAL.is_file():
        return _HTTP_DEFAULT_PASSWORDS_LOCAL

    logger.info("No HTTP default-password list found — fetching from SecLists")
    if _download(_HTTP_DEFAULT_PASSWORDS_URL, _HTTP_DEFAULT_PASSWORDS_LOCAL):
        return _HTTP_DEFAULT_PASSWORDS_LOCAL

    return None
