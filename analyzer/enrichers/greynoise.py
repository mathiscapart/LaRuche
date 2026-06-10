"""Enrichissement GreyNoise (US-31) : mass scanner vs activité ciblée.

Pour chaque IP : interroge l'API GreyNoise Community et renseigne
`greynoise_classification` (malicious / benign / unknown) et `greynoise_name`.
Cache SQLite (1 appel par IP max) + throttling 1 req/s. Les IP privées sont
bypassées sans appel réseau. Sans clé API (GREYNOISE_API_KEY), renvoie 'unknown'.
"""

from __future__ import annotations

import ipaddress
import sqlite3
import time
from pathlib import Path

import httpx

from analyzer.config import GREYNOISE_API_KEY, GREYNOISE_CACHE, GREYNOISE_MIN_INTERVAL

_API_URL = "https://api.greynoise.io/v3/community/{ip}"
_UNKNOWN = {"greynoise_classification": "unknown", "greynoise_name": ""}


def _is_public(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class GreyNoiseEnricher:
    """Enricher GreyNoise avec cache SQLite persistant et throttling."""

    def __init__(
        self,
        api_key: str = GREYNOISE_API_KEY,
        cache_path: str = GREYNOISE_CACHE,
        min_interval: float = GREYNOISE_MIN_INTERVAL,
    ) -> None:
        self._api_key = api_key
        self._min_interval = min_interval
        self._last_call = 0.0
        Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(cache_path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS greynoise "
            "(ip TEXT PRIMARY KEY, classification TEXT, name TEXT, ts REAL)"
        )
        self._db.commit()

    def _cached(self, ip: str) -> dict | None:
        row = self._db.execute(
            "SELECT classification, name FROM greynoise WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return None
        return {"greynoise_classification": row[0], "greynoise_name": row[1]}

    def _store(self, ip: str, data: dict) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO greynoise (ip, classification, name, ts) VALUES (?, ?, ?, ?)",
            (ip, data["greynoise_classification"], data["greynoise_name"], time.time()),
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
                _API_URL.format(ip=ip), headers={"key": self._api_key}, timeout=5.0
            )
        except httpx.HTTPError:
            return dict(_UNKNOWN)
        if resp.status_code != 200:
            return dict(_UNKNOWN)
        try:
            body = resp.json()
        except ValueError:
            return dict(_UNKNOWN)
        return {
            "greynoise_classification": body.get("classification", "unknown"),
            "greynoise_name": body.get("name", ""),
        }

    def enrich(self, ip: str) -> dict:
        """Renvoie les champs GreyNoise pour une IP (cache > API > unknown)."""
        if not _is_public(ip):
            return dict(_UNKNOWN)
        cached = self._cached(ip)
        if cached is not None:
            return cached
        if not self._api_key:
            return dict(_UNKNOWN)
        data = self._query_api(ip)
        self._store(ip, data)
        return data

    def close(self) -> None:
        self._db.close()
