# Honeypot SSH (EPIC-1) — image minimale, exécutée en non-root.
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
# l'environnement (cf. config.py), rien à lire sur le filesystem.
COPY config.py commands.py detection.py events.py server.py ./

# Utilisateur non privilégié + répertoire de logs inscriptible par lui.
RUN useradd --system --no-create-home --uid 10001 honey \
    && mkdir -p /var/log/honeypot \
    && chown honey:honey /var/log/honeypot
USER honey

# Port d'écoute par défaut (surchargé par SSH_BIND_PORT).
EXPOSE 2222

# Vérifie que le port SSH accepte les connexions TCP.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import socket,os,sys; s=socket.socket(); s.settimeout(3); sys.exit(s.connect_ex(('127.0.0.1', int(os.getenv('SSH_BIND_PORT','2222')))))"

ENTRYPOINT ["python", "server.py"]
