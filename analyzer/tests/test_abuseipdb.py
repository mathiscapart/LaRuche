"""Tests de l'enricher AbuseIPDB (US-19)."""

from analyzer.enrichers.abuseipdb import AbuseIPDBEnricher


def _enricher(tmp_path, api_key=""):
    return AbuseIPDBEnricher(
        api_key=api_key, cache_path=str(tmp_path / "abuse.sqlite"), min_interval=0.0
    )


def test_private_ip_neutral(tmp_path) -> None:
    ab = _enricher(tmp_path, api_key="x")
    assert ab.enrich("192.168.1.10") == {"abuse_score": 0, "is_tor": False, "country_code": ""}
    ab.close()


def test_no_api_key_returns_neutral(tmp_path) -> None:
    ab = _enricher(tmp_path, api_key="")
    assert ab.enrich("8.8.8.8")["abuse_score"] == 0
    ab.close()


def test_cache_hit_short_circuits(tmp_path) -> None:
    ab = _enricher(tmp_path, api_key="x")
    ab._store("8.8.8.8", {"abuse_score": 92, "is_tor": True, "country_code": "US"})
    out = ab.enrich("8.8.8.8")
    assert out == {"abuse_score": 92, "is_tor": True, "country_code": "US"}
    ab.close()
