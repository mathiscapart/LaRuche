# syntax=docker/dockerfile:1
# Analyzer LaRuche (EPIC-4) — enrichissement des events honeypot.
# Lit les JSONL bruts (volume partagé), écrit les events enrichis pour Fluent Bit.
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Build context = racine du repo (cf. docker-compose : dockerfile analyzer/Dockerfile).
COPY analyzer/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer ./analyzer

# Utilisateur non privilégié + répertoires inscriptibles (cache API, sortie enrichie).
RUN useradd --system --no-create-home --uid 10001 honey \
    && mkdir -p /var/log/honeypot/enriched /app/.cache \
    && chown -R honey:honey /var/log/honeypot/enriched /app/.cache
USER honey

# Boucle d'enrichissement (lit le brut, écrit l'enrichi toutes les ANALYZER_INTERVAL s).
CMD ["python", "-m", "analyzer.enrich"]
