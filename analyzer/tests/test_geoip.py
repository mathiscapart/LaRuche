"""Tests de l'enricher GeoIP (US-19) — comportement sans base .mmdb."""

from analyzer.enrichers.geoip import GeoIPEnricher

_FIELDS = {"country_code", "country_name", "city", "asn", "org"}


def test_returns_empty_fields_without_database() -> None:
    # Bases absentes (chemins bidon) => champs présents mais vides, sans erreur.
    gn = GeoIPEnricher(city_db="/nope/city.mmdb", asn_db="/nope/asn.mmdb")
    out = gn.enrich("8.8.8.8")
    assert set(out) == _FIELDS
    assert all(v == "" for v in out.values())
    gn.close()


def test_private_ip_bypassed() -> None:
    gn = GeoIPEnricher(city_db="/nope/city.mmdb", asn_db="/nope/asn.mmdb")
    assert gn.enrich("10.0.0.1")["country_code"] == ""
    gn.close()
