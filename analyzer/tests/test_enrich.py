"""Tests de l'orchestrateur d'enrichissement (analyzer.enrich)."""

import json

from analyzer.classifier import BehaviorClassifier
from analyzer.enrich import Enricher, run_once
from analyzer.enrichers.abuseipdb import AbuseIPDBEnricher
from analyzer.enrichers.geoip import GeoIPEnricher
from analyzer.enrichers.greynoise import GreyNoiseEnricher


def _enricher(tmp_path):
    return Enricher(
        geo=GeoIPEnricher(city_db="/nope.mmdb", asn_db="/nope.mmdb"),
        abuse=AbuseIPDBEnricher(api_key="", cache_path=str(tmp_path / "a.sqlite"), min_interval=0.0),
        greynoise=GreyNoiseEnricher(api_key="", cache_path=str(tmp_path / "g.sqlite"), min_interval=0.0),
        classifier=BehaviorClassifier(),
    )


def test_enrich_event_fills_enrichment_block(tmp_path) -> None:
    enr = _enricher(tmp_path)
    event = {"id": "1", "src_ip": "8.8.8.8", "event_type": "request", "payload": {}}
    enr.enrich_event(event, profile="scanner")
    assert set(event["enrichment"]) >= {"country_code", "abuse_score", "greynoise", "is_tor"}
    assert event["enrichment"]["greynoise"] == "unknown"
    assert event["classification"]["profile"] == "scanner"
    enr.close()


def test_run_once_writes_enriched_and_dedups(tmp_path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    # 12 tentatives d'auth depuis la même IP -> session bruteforcer.
    lines = [
        json.dumps({"id": str(i), "src_ip": "45.33.32.156", "session_id": "s1",
                    "event_type": "credential_attempt",
                    "timestamp": f"2026-06-01T12:00:{i:02d}.000Z", "payload": {}})
        for i in range(12)
    ]
    (logs / "http.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = tmp_path / "enriched" / "events.jsonl"

    enr = _enricher(tmp_path)
    n1 = run_once(log_dir=logs, out_path=out, enricher=enr)
    n2 = run_once(log_dir=logs, out_path=out, enricher=enr)  # rien de neuf -> dédup
    enr.close()

    assert n1 == 12
    assert n2 == 0
    enriched = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(enriched) == 12
    assert all("enrichment" in e for e in enriched)
    assert enriched[0]["classification"]["profile"] == "bruteforcer"
