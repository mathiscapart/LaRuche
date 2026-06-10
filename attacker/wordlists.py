from __future__ import annotations

import logging
import urllib.request
from pathlib import Path

from attacker.config import WORDLISTS_DIR

logger = logging.getLogger(__name__)

_DIRSEARCH_WORDLIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Discovery/Web-Content/raft-medium-directories.txt"
)

_PASSWORD_WORDLIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Passwords/Common-Credentials/Pwdb_top-10000.txt"
)

_USERNAME_WORDLIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    "/Usernames/top-usernames-shortlist.txt"
)

_DIRSEARCH_WORDLIST_LOCAL: Path = WORDLISTS_DIR / "directories.txt"
_PASSWORD_WORDLIST_LOCAL: Path = WORDLISTS_DIR / "passwords.txt"
_USERNAME_WORDLIST_LOCAL: Path = WORDLISTS_DIR / "usernames.txt"


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

    logger.info(
        "No dirsearch wordlist found — fetching raft-medium-directories from SecLists"
    )
    if _download(_DIRSEARCH_WORDLIST_URL, _DIRSEARCH_WORDLIST_LOCAL):
        return _DIRSEARCH_WORDLIST_LOCAL

    return None


def ensure_password_wordlist() -> Path | None:
    if _PASSWORD_WORDLIST_LOCAL.is_file():
        return _PASSWORD_WORDLIST_LOCAL

    logger.info(
        "No FTP password wordlist found — fetching 10k common passwords from SecLists"
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
