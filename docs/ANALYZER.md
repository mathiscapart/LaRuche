# Analyzer — enrichissement des events (EPIC-4)

Service Python qui transforme les events bruts des honeypots en events
**enrichis** : il ajoute le bloc `enrichment` (géolocalisation, réputation,
scanner connu) et `classification.profile` (profil comportemental), puis réécrit
le résultat pour Fluent Bit → OpenObserve. Pas de SIEM, pas de broker.

## Place dans le pipeline

```
honeypots → /var/log/honeypot/*.jsonl (brut)
          → [analyzer : enrichissement, boucle 10 s]
          → /var/log/honeypot/enriched/events.jsonl
          → Fluent Bit → OpenObserve (stream honeypot_events)
```

L'analyzer (`compose.yml` service `analyzer`) **partage le volume `honeypot_logs`**
avec les honeypots : il lit le brut (RW), écrit l'enrichi dans le même volume sous
`enriched/`. Fluent Bit ne tail **que** `enriched/*.jsonl`.

## Les 3 enrichers

| Enricher | Type | Source | Clé / base | Renvoie |
|---|---|---|---|---|
| **GeoIP** (`enrichers/geoip.py`) | Base **locale** (0 réseau) | MaxMind GeoLite2 City + ASN | `.mmdb` (téléchargés via license) | `country_code`, `country_name`, `city`, `asn`, `org`, `latitude`, `longitude` |
| **AbuseIPDB** (`enrichers/abuseipdb.py`) | **API REST** en ligne | `api.abuseipdb.com/api/v2/check` | `ABUSEIPDB_API_KEY` (header `Key`) | `abuse_score` (0-100), `is_tor`, `country_code` |
| **GreyNoise** (`enrichers/greynoise.py`) | **API REST** en ligne | `api.greynoise.io/v3/community/{ip}` | `GREYNOISE_API_KEY` (header `key`) | `greynoise` (`malicious`/`benign`/`unknown`), `greynoise_name` |

**Point clé** : GeoIP ne fait **aucun** appel réseau au runtime — c'est une lecture
locale du `.mmdb`. La license MaxMind sert **uniquement** à télécharger la base.
AbuseIPDB et GreyNoise sont de vraies API interrogées par IP.

### Cache & throttling (API)
AbuseIPDB et GreyNoise mettent en cache **SQLite** chaque IP (1 seul appel par IP)
et espacent les requêtes (`*_MIN_INTERVAL`, 1 s par défaut). Indispensable : le
plan gratuit AbuseIPDB est limité à 1000 checks/jour.

### Dégradation gracieuse
Tout est best-effort : **clé absente / base `.mmdb` absente / erreur HTTP / IP
privée** → champs neutres (vides, `abuse_score: 0`, `greynoise: unknown`), **jamais
de crash**. Les IP privées sont bypassées sans appel réseau (non géolocalisables).

## Classifier de profil (US-30)

`classifier.py` regroupe les events par session et attribue un profil
comportemental — `bot`, `bruteforcer`, `scanner` ou `human` — écrit dans
`classification.profile`. (Matrice de confusion + métriques disponibles pour
l'évaluation.)

## Bloc `enrichment` produit

Conforme à `docs/event.schema.json` :

| Champ | Origine | Exemple (`71.6.199.23`, scanner Shodan) |
|---|---|---|
| `country_code` / `country_name` / `city` | GeoIP City | `US` / `United States` / `""` |
| `latitude` / `longitude` | GeoIP City | `32.9…` / `-117.0…` (`null` si inconnu) |
| `asn` / `org` | GeoIP ASN | `AS10439` / `CariNet, Inc.` |
| `abuse_score` / `is_tor` | AbuseIPDB | `100` / `false` |
| `greynoise` / `greynoise_name` | GreyNoise | `benign` / `Shodan.io` |

## Configuration (variables d'env — `config.py`)

| Variable | Défaut | Rôle |
|---|---|---|
| `ANALYZER_LOG_DIR` | `/var/log/honeypot` | dossier des JSONL bruts |
| `ANALYZER_ENRICHED_OUTPUT` | `/var/log/honeypot/enriched/events.jsonl` | sortie enrichie |
| `ANALYZER_INTERVAL` | `10` | période de la boucle (s) |
| `GEOIP_CITY_DB` / `GEOIP_ASN_DB` | `/data/geoip/GeoLite2-*.mmdb` | bases MaxMind |
| `ABUSEIPDB_API_KEY` / `GREYNOISE_API_KEY` | *(vide)* | clés API (vide ⇒ neutre) |
| `ABUSEIPDB_CACHE` / `GREYNOISE_CACHE` | `.cache/*.sqlite` | cache de réputation |
| `ABUSEIPDB_MIN_INTERVAL` / `GREYNOISE_MIN_INTERVAL` | `1.0` | throttle (s) |

## Bases GeoLite2 (à fournir)

Non versionnées (54 Mo + licence MaxMind non-redistribuable → cf. `.gitignore`).
Téléchargement avec une license key MaxMind :

```bash
mkdir -p data/geoip
for ed in GeoLite2-City GeoLite2-ASN; do
  tmp=$(mktemp -d)
  curl -sSL "https://download.maxmind.com/app/geoip_download?edition_id=$ed&license_key=$MAXMIND_LICENSE_KEY&suffix=tar.gz" -o "$tmp/$ed.tar.gz"
  tar -xzf "$tmp/$ed.tar.gz" -C "$tmp"
  find "$tmp" -name "$ed.mmdb" -exec mv {} "data/geoip/$ed.mmdb" \;
done
```

(montées en lecture seule dans le conteneur via `./data/geoip:/data/geoip:ro`).

## Clés API & secrets

- **Local** : `.env` (gitignoré) — voir `.env.example`. Compose substitue
  `${ABUSEIPDB_API_KEY:-}` / `${GREYNOISE_API_KEY:-}` dans le service `analyzer`.
- **CI/CD** : GitHub Actions Secrets (`Settings → Secrets and variables → Actions`).
  Le job **`enrich`** de `.github/workflows/ci.yml` lance les 3 enrichers en live
  contre une IP publique connue et échoue si un secret est absent ou faux — il
  valide donc le câblage des secrets sans monter la stack.

> Les secrets ne sont **jamais** committés (ni clés API, ni `.mmdb`).

## Lancement

```bash
# Dans la stack (recommandé)
docker compose up -d --build analyzer

# En standalone (depuis la racine du repo)
python -m analyzer.enrich            # boucle run_forever (ANALYZER_INTERVAL)
```

`enrich.run_once()` est idempotent : les events déjà enrichis sont dédupliqués
par `id` (pas de double traitement entre deux passes).

## Tests

```bash
pytest analyzer/        # tests unitaires (enrichers mockés, classifier, run_once)
```

Le job CI `enrich` complète avec une validation **live** des clés réelles.
