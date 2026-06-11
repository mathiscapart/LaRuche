# syntax=docker/dockerfile:1
# Analyzer LaRuche (EPIC-4) — enrichissement des events honeypot.
# Lit les JSONL bruts (volume partagé), écrit les events enrichis pour Fluent Bit.

# --- Stage 1 : bases GeoLite2 bakées dans l'image (layer jetable) ---------
# Téléchargement en Python stdlib (pas de curl/apt, pas de pipe -> hadolint OK).
# Le secret MAXMIND_LICENSE_KEY reste dans ce stage discardé, jamais dans
# l'image finale. /geoip reste vide si la clé est absente au build.
FROM python:3.12-slim-bookworm AS geoip-fetch
ARG MAXMIND_LICENSE_KEY=""
COPY analyzer/fetch_geoip.py /usr/local/bin/fetch_geoip.py
RUN MAXMIND_LICENSE_KEY="$MAXMIND_LICENSE_KEY" python /usr/local/bin/fetch_geoip.py /geoip

# --- Stage 2 : image finale -----------------------------------------------
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Build context = racine du repo (cf. docker-compose : dockerfile analyzer/Dockerfile).
COPY analyzer/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer ./analyzer

# Bases GeoLite2 embarquées depuis le stage de fetch (vides si clé absente au build).
COPY --from=geoip-fetch /geoip /data/geoip

# Utilisateur non privilégié + répertoires inscriptibles (cache API, sortie enrichie).
RUN useradd --system --no-create-home --uid 10001 honey \
    && mkdir -p /var/log/honeypot/enriched /app/.cache \
    && chown -R honey:honey /var/log/honeypot/enriched /app/.cache
USER honey

# Boucle d'enrichissement (lit le brut, écrit l'enrichi toutes les ANALYZER_INTERVAL s).
CMD ["python", "-m", "analyzer.enrich"]
