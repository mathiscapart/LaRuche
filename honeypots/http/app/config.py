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


# --- Faux login WordPress (hardening anti-détection, comme le honeypot SSH) ---
def _parse_credentials(raw: str) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for item in raw.split(","):
        cleaned = item.strip()
        if ":" in cleaned:
            user, _, password = cleaned.partition(":")
            pairs.add((user, password))
    return pairs


# Couples FAIBLES acceptés par le faux login. Accepter n'importe quel couple
# serait un tell de honeypot : tout le reste est refusé.
ALLOWED_WP_CREDENTIALS = _parse_credentials(
    os.getenv("WP_ALLOWED_CREDENTIALS", "admin:admin,admin:admin123,administrator:password123")
)
# Cookie d'auth posé après un login réussi (forme d'un vrai WordPress).
LOGGED_IN_COOKIE = "wordpress_logged_in_" + os.getenv("WP_COOKIE_HASH", "8d2a1f4c9b7e6051")

# Jitter de latence (anti-fingerprint temporel, comme le honeypot SSH).
# Mettre HTTP_JITTER_MAX_MS=0 pour désactiver (tests).
JITTER_MIN_MS = int(os.getenv("HTTP_JITTER_MIN_MS", "50"))
JITTER_MAX_MS = int(os.getenv("HTTP_JITTER_MAX_MS", "300"))
