"""Configuration du honeypot HTTP : headers cohérents et constantes d'émulation.

Chaque réponse imite un serveur Apache/PHP réel pour rester crédible face aux
scanners (cohérence imposée par US-08 et US-28).
"""

# Headers renvoyés sur CHAQUE réponse (US-08 / US-28).
SERVER_HEADER = "Apache/2.4.57 (Debian)"
X_POWERED_BY = "PHP/7.4.33"

COHERENT_HEADERS = {
    "Server": SERVER_HEADER,
    "X-Powered-By": X_POWERED_BY,
}

# Port d'écoute interne du conteneur (l'hôte de bind est fourni par uvicorn/Docker).
LISTEN_PORT = 8080
