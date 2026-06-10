"""Enrichissement AbuseIPDB (US-19) : score de réputation, is_tor, pays.

Cache SQLite (1 appel par IP) + throttling. IP privées bypassées. Sans clé API
(ABUSEIPDB_API_KEY), renvoie un score neutre (0) sans appel réseau.
"""

from __future__ import annotations

import ipaddress
import sqlite3
import time
from pathlib import Path

import httpx

from analyzer.config import ABUSEIPDB_API_KEY, ABUSEIPDB_CACHE, ABUSEIPDB_MIN_INTERVAL

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_EMPTY = {"abuse_score": 0, "is_tor": False, "country_code": ""}


def _is_public(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class AbuseIPDBEnricher:
    """Enricher AbuseIPDB avec cache SQLite et throttling."""

    def __init__(
        self,
        api_key: str = ABUSEIPDB_API_KEY,
        cache_path: str = ABUSEIPDB_CACHE,
        min_interval: float = ABUSEIPDB_MIN_INTERVAL,
    ) -> None:
        self._api_key = api_key
        self._min_interval = min_interval
        self._last_call = 0.0
        Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(cache_path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS abuseipdb "
            "(ip TEXT PRIMARY KEY, score INTEGER, is_tor INTEGER, country TEXT, ts REAL)"
        )
        self._db.commit()

    def _cached(self, ip: str) -> dict | None:
        row = self._db.execute(
            "SELECT score, is_tor, country FROM abuseipdb WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return None
        return {"abuse_score": row[0], "is_tor": bool(row[1]), "country_code": row[2]}

    def _store(self, ip: str, data: dict) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO abuseipdb (ip, score, is_tor, country, ts) "
            "VALUES (?, ?, ?, ?, ?)",
            (ip, data["abuse_score"], int(data["is_tor"]), data["country_code"], time.time()),
        )
        self._db.commit()

    def _throttle(self) -> None:
        wait = self._min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def _query_api(self, ip: str) -> dict:
        self._throttle()
        try:
            resp = httpx.get(
                _API_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=10.0,
            )
        except httpx.HTTPError:
            return dict(_EMPTY)
        if resp.status_code != 200:
            return dict(_EMPTY)
        try:
            data = resp.json()["data"]
        except (ValueError, KeyError):
            return dict(_EMPTY)
        return {
            "abuse_score": int(data.get("abuseConfidenceScore", 0)),
            "is_tor": bool(data.get("isTor", False)),
            "country_code": data.get("countryCode") or "",
        }

    def enrich(self, ip: str) -> dict:
        """Renvoie {abuse_score, is_tor, country_code} (cache > API > neutre)."""
        if not _is_public(ip):
            return dict(_EMPTY)
        cached = self._cached(ip)
        if cached is not None:
            return cached
        if not self._api_key:
            return dict(_EMPTY)
        data = self._query_api(ip)
        self._store(ip, data)
        return data

    def close(self) -> None:
        self._db.close()
