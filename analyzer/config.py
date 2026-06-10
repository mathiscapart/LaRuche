"""Configuration de l'analyzer (EPIC-4, version simplifiée).

Pipeline : honeypots -> JSONL -> [analyzer : enrichissement] -> OpenObserve.
Pas de SIEM (Wazuh retiré), pas de Sigma : on se concentre sur l'enrichissement.
Tout est lu depuis l'environnement (12-factor) ; clés API fournies par l'école.
"""

import os

# Entrée : les JSONL bruts produits par les honeypots.
LOG_DIR = os.getenv("ANALYZER_LOG_DIR", "/var/log/honeypot")
# Sortie : events enrichis (append), tailés par Fluent Bit -> OpenObserve.
ENRICHED_OUTPUT = os.getenv("ANALYZER_ENRICHED_OUTPUT", "/var/log/honeypot/enriched/events.jsonl")
# Fréquence de la passe d'enrichissement (s) — aligné sur le refresh dashboard (US-19).
ENRICH_INTERVAL_SECONDS = int(os.getenv("ANALYZER_INTERVAL", "10"))

# GeoIP (US-19) : bases MaxMind GeoLite2 (City + ASN).
GEOIP_CITY_DB = os.getenv("GEOIP_CITY_DB", "/data/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.getenv("GEOIP_ASN_DB", "/data/geoip/GeoLite2-ASN.mmdb")

# AbuseIPDB (US-19) : score de réputation.
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_CACHE = os.getenv("ABUSEIPDB_CACHE", ".cache/abuseipdb.sqlite")
ABUSEIPDB_MIN_INTERVAL = float(os.getenv("ABUSEIPDB_MIN_INTERVAL", "1.0"))

# GreyNoise (US-31) : mass scanner vs activité ciblée.
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
GREYNOISE_CACHE = os.getenv("GREYNOISE_CACHE", ".cache/greynoise.sqlite")
GREYNOISE_MIN_INTERVAL = float(os.getenv("GREYNOISE_MIN_INTERVAL", "1.0"))
