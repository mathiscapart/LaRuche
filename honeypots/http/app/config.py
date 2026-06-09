"""Configuration du honeypot HTTP : headers cohérents et constantes d'émulation.

Chaque réponse imite un serveur Apache/PHP réel pour rester crédible face aux
scanners (cohérence imposée par US-08 et US-28).
"""

import os

# Headers renvoyés sur CHAQUE réponse (US-08 / US-28).
SERVER_HEADER = "Apache/2.4.57 (Debian)"
X_POWERED_BY = "PHP/7.4.33"

COHERENT_HEADERS = {
    "Server": SERVER_HEADER,
    "X-Powered-By": X_POWERED_BY,
}

# Port d'écoute interne du conteneur (l'hôte de bind est fourni par uvicorn/Docker).
LISTEN_PORT = 8080

# Journalisation des événements (JSON Lines) — voir app/events/builder.py.
# Même dossier/convention que le honeypot SSH (/var/log/honeypot/<service>.jsonl).
LOG_FILE = os.getenv("HTTP_LOG_FILE", "/var/log/honeypot/http.jsonl")
# Hostname simulé : identique au SSH pour que le SIEM corrèle une seule machine.
HONEYPOT_HOST = os.getenv("HONEYPOT_HOST", "prod-srv-01")
SCHEMA_VERSION = "1.0.0"

# Alertes canary (US-11) poussées vers Redis.
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
ALERT_CHANNEL = os.getenv("ALERT_CHANNEL", "honeypot:alerts")
