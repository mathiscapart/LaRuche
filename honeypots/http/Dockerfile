# syntax=docker/dockerfile:1
# Honeypot HTTP (EPIC-2) — émulation WordPress, image minimale, exécutée en non-root.
FROM python:3.12-slim-bookworm

# Empêche Python de bufferiser stdout : les événements JSONL sortent en temps
# réel dans les logs Docker / vers Filebeat.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Dépendances d'abord (cache de build).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code applicatif.
COPY app ./app
COPY alerts ./alerts

# Utilisateur non privilégié + répertoire de logs inscriptible (aligné SSH).
RUN useradd --system --no-create-home --uid 10001 honey \
    && mkdir -p /var/log/honeypot \
    && chown honey:honey /var/log/honeypot
USER honey

EXPOSE 8080

# Vérifie que le port HTTP accepte les connexions TCP.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import socket,os,sys; s=socket.socket(); s.settimeout(3); sys.exit(s.connect_ex(('127.0.0.1', int(os.getenv('HTTP_PORT','8080')))))"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
