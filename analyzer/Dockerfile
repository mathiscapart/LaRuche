# syntax=docker/dockerfile:1
# Analyzer LaRuche (EPIC-4) — enrichissement des events honeypot.
# Lit les JSONL bruts (volume partagé), écrit les events enrichis pour Fluent Bit.

# --- Stage 1 : téléchargement des bases GeoLite2 (layer jetable) ----------
# Le secret MAXMIND_LICENSE_KEY n'apparaît pas dans l'image finale.
FROM python:3.12-slim-bookworm AS geoip-fetch
ARG MAXMIND_LICENSE_KEY=""
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /geoip && \
    if [ -n "$MAXMIND_LICENSE_KEY" ]; then \
      for ed in GeoLite2-City GeoLite2-ASN; do \
        curl -sSL "https://download.maxmind.com/app/geoip_download?edition_id=${ed}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
          | tar -xz --strip-components=1 --wildcards -C /geoip "*/${ed}.mmdb"; \
      done; \
    fi

# --- Stage 2 : image finale -----------------------------------------------
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Build context = racine du repo (cf. docker-compose : dockerfile analyzer/Dockerfile).
COPY analyzer/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer ./analyzer

# Bases GeoLite2 embarquées (vides si MAXMIND_LICENSE_KEY absent au build).
COPY --from=geoip-fetch /geoip /data/geoip

# Utilisateur non privilégié + répertoires inscriptibles (cache API, sortie enrichie).
RUN useradd --system --no-create-home --uid 10001 honey \
    && mkdir -p /var/log/honeypot/enriched /app/.cache \
    && chown -R honey:honey /var/log/honeypot/enriched /app/.cache
USER honey

# Boucle d'enrichissement (lit le brut, écrit l'enrichi toutes les ANALYZER_INTERVAL s).
CMD ["python", "-m", "analyzer.enrich"]
