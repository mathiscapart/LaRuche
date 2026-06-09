# Honeypot FTP (EPIC-1) — image minimale, exécutée en non-root.
FROM python:3.12-slim-bookworm

# Empêche Python de bufferiser stdout : les événements JSONL sortent en
# temps réel dans les logs Docker / vers Filebeat.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Dépendances d'abord (cache de build).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code applicatif. Aucune configuration n'est copiée : tout passe par
# l'environnement (cf. config.py). L'arborescence leurre est matérialisée au
# démarrage par filesystem.py — rien de réel n'est exposé.
COPY config.py detection.py events.py filesystem.py server.py ./

# Utilisateur non privilégié + répertoires inscriptibles par lui (logs et
# racine leurre matérialisée au démarrage).
RUN useradd --system --no-create-home --uid 10001 honey \
    && mkdir -p /var/log/honeypot /srv/ftp \
    && chown -R honey:honey /var/log/honeypot /srv/ftp
USER honey

# Port de contrôle par défaut (surchargé par FTP_BIND_PORT). Le mode passif
# utilise la plage FTP_PASV_MIN..MAX, à exposer côté docker-compose.
EXPOSE 2121

# Vérifie que le port de contrôle FTP accepte les connexions TCP.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import socket,os,sys; s=socket.socket(); s.settimeout(3); sys.exit(s.connect_ex(('127.0.0.1', int(os.getenv('FTP_BIND_PORT','2121')))))"

ENTRYPOINT ["python", "server.py"]
