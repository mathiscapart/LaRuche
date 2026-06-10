"""Enrichissement GeoIP via MaxMind GeoLite2 (US-19).

Renseigne pays / ville / ASN / organisation depuis les bases locales GeoLite2
(City + ASN). Sans base (.mmdb absent) ou pour une IP privée : champs vides.
"""

from __future__ import annotations

import ipaddress

from analyzer.config import GEOIP_ASN_DB, GEOIP_CITY_DB

try:
    import geoip2.database
except ImportError:  # geoip2 optionnel (champs vides si absent)
    geoip2 = None

_EMPTY = {"country_code": "", "country_name": "", "city": "", "asn": "", "org": ""}


def _open_reader(path: str):
    if geoip2 is None:
        return None
    try:
        return geoip2.database.Reader(path)
    except (OSError, ValueError):
        return None


class GeoIPEnricher:
    """Lecteur GeoLite2 City + ASN (best-effort)."""

    def __init__(self, city_db: str = GEOIP_CITY_DB, asn_db: str = GEOIP_ASN_DB) -> None:
        self._city = _open_reader(city_db)
        self._asn = _open_reader(asn_db)

    def enrich(self, ip: str) -> dict:
        out = dict(_EMPTY)
        try:
            if ipaddress.ip_address(ip).is_private:
                return out
        except ValueError:
            return out
        if self._city is not None:
            try:
                city = self._city.city(ip)
                out["country_code"] = city.country.iso_code or ""
                out["country_name"] = city.country.name or ""
                out["city"] = city.city.name or ""
            except Exception:  # IP absente de la base, etc.
                pass
        if self._asn is not None:
            try:
                asn = self._asn.asn(ip)
                number = asn.autonomous_system_number
                out["asn"] = f"AS{number}" if number else ""
                out["org"] = asn.autonomous_system_organization or ""
            except Exception:
                pass
        return out

    def close(self) -> None:
        for reader in (self._city, self._asn):
            if reader is not None:
                reader.close()
