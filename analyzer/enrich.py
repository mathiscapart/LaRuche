"""Orchestrateur d'enrichissement (EPIC-4, version simplifiée).

Lit les events JSONL bruts des honeypots, ajoute le bloc `enrichment` (GeoIP +
AbuseIPDB + GreyNoise) et `classification.profile` (classifier US-30), puis écrit
les events enrichis en append (dédupliqués par `id`) dans un fichier tailé par
Fluent Bit -> OpenObserve. Pas de SIEM, pas d'export : juste l'enrichissement.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable
from pathlib import Path

from analyzer.classifier import BehaviorClassifier
from analyzer.config import ENRICH_INTERVAL_SECONDS, ENRICHED_OUTPUT, LOG_DIR
from analyzer.enrichers.abuseipdb import AbuseIPDBEnricher
from analyzer.enrichers.geoip import GeoIPEnricher
from analyzer.enrichers.greynoise import GreyNoiseEnricher
from analyzer.events import group_by_session, iter_events, load_log_dir


def _session_key(event: dict) -> str:
    return event.get("session_id") or event.get("src_ip") or "unknown"


class Enricher:
    """Combine les 3 enrichers + le classifier de profil. Cache d'enrichissement par IP."""

    def __init__(self, geo=None, abuse=None, greynoise=None, classifier=None) -> None:
        self._geo = geo or GeoIPEnricher()
        self._abuse = abuse or AbuseIPDBEnricher()
        self._greynoise = greynoise or GreyNoiseEnricher()
        self._classifier = classifier or BehaviorClassifier()
        self._ip_cache: dict[str, dict] = {}

    def enrichment_for(self, ip: str) -> dict:
        if ip not in self._ip_cache:
            geo = self._geo.enrich(ip)
            abuse = self._abuse.enrich(ip)
            greynoise = self._greynoise.enrich(ip)
            self._ip_cache[ip] = {
                **geo,
                "abuse_score": abuse["abuse_score"],
                "is_tor": abuse["is_tor"],
                "greynoise": greynoise["greynoise_classification"],
                "greynoise_name": greynoise["greynoise_name"],
            }
        return dict(self._ip_cache[ip])

    def session_profiles(self, events: Iterable[dict]) -> dict[str, str]:
        return {
            key: self._classifier.classify_session(group)
            for key, group in group_by_session(events).items()
        }

    def enrich_event(self, event: dict, profile: str | None = None) -> dict:
        event.setdefault("enrichment", {}).update(self.enrichment_for(event.get("src_ip", "")))
        if profile:
            event.setdefault("classification", {})["profile"] = profile
        return event

    def close(self) -> None:
        self._geo.close()
        self._abuse.close()
        self._greynoise.close()


def run_once(
    log_dir: Path | str = LOG_DIR,
    out_path: Path | str = ENRICHED_OUTPUT,
    enricher: Enricher | None = None,
) -> int:
    """Enrichit les events non encore traités et les append à la sortie. Renvoie le nb traité."""
    owns = enricher is None
    enricher = enricher or Enricher()
    try:
        raw = load_log_dir(log_dir)
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        already_seen = {event.get("id") for event in iter_events([out])}
        fresh = [event for event in raw if event.get("id") not in already_seen]
        if not fresh:
            return 0
        profiles = enricher.session_profiles(raw)
        with out.open("a", encoding="utf-8") as handle:
            for event in fresh:
                enricher.enrich_event(event, profiles.get(_session_key(event)))
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        return len(fresh)
    finally:
        if owns:
            enricher.close()


async def run_forever(interval: int = ENRICH_INTERVAL_SECONDS) -> None:  # pragma: no cover
    enricher = Enricher()
    try:
        while True:
            run_once(enricher=enricher)
            await asyncio.sleep(interval)
    finally:
        enricher.close()


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(run_forever())
