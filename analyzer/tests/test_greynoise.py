"""Tests de l'enricher GreyNoise (US-31)."""

from analyzer.enrichers.greynoise import GreyNoiseEnricher


def _enricher(tmp_path, api_key=""):
    return GreyNoiseEnricher(api_key=api_key, cache_path=str(tmp_path / "gn.sqlite"), min_interval=0.0)


def test_private_ip_bypassed_without_api(tmp_path) -> None:
    gn = _enricher(tmp_path, api_key="should-not-be-used")
    out = gn.enrich("10.0.0.5")
    assert out["greynoise_classification"] == "unknown"
    gn.close()


def test_invalid_ip_returns_unknown(tmp_path) -> None:
    gn = _enricher(tmp_path)
    assert gn.enrich("not-an-ip")["greynoise_classification"] == "unknown"
    gn.close()


def test_no_api_key_returns_unknown_without_call(tmp_path) -> None:
    gn = _enricher(tmp_path, api_key="")
    assert gn.enrich("8.8.8.8") == {"greynoise_classification": "unknown", "greynoise_name": ""}
    gn.close()


def test_cache_hit_short_circuits(tmp_path) -> None:
    gn = _enricher(tmp_path, api_key="x")
    gn._store("8.8.8.8", {"greynoise_classification": "malicious", "greynoise_name": "Mirai"})
    out = gn.enrich("8.8.8.8")  # doit lire le cache, pas l'API
    assert out == {"greynoise_classification": "malicious", "greynoise_name": "Mirai"}
    gn.close()
