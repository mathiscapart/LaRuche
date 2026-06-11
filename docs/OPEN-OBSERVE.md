# Dashboards OpenObserve (US-19)

Dashboards versionnés en JSON (façon provisioning Grafana). La source de vérité
est `openobserve/dashboards/*.json` ; ils s'importent tels quels via l'UI
OpenObserve (**Dashboards → Import**) ou via le provisioning automatique.

## Import

**Automatique au démarrage de la stack.** Le service `dashboard-provisioner`
(dans `compose.yml`) attend qu'OpenObserve réponde, puis importe tous les
`dashboards/*.json` — à chaque `docker compose up`. Conteneur one-shot qui
s'arrête une fois l'import fait (`restart: "no"`).

**Manuel** (hors stack, ou pour réimporter après édition) :

```bash
python3 openobserve/provision.py
```

Stdlib uniquement, aucune dépendance. Config via l'environnement (défauts =
stack locale `localhost:5080` / `admin@laruche.local`) : `OPENOBSERVE_URL`,
`OPENOBSERVE_ORG`, `OPENOBSERVE_USER`, `OPENOBSERVE_PASSWORD`, `DASHBOARDS_DIR`.

L'import est idempotent : un dashboard de même titre est supprimé puis recréé
(OpenObserve régénère le `dashboardId` à l'import, donc on déduplique par titre).

## Dashboards

| Fichier | Titre | État |
|---|---|---|
| `global.json` | Honeypot — Global | ✅ fonctionnel |
| `ssh.json` | Honeypot — SSH | ✅ fonctionnel |
| `ftp.json` | Honeypot — FTP | ✅ fonctionnel |
| `http.json` | Honeypot — HTTP | ✅ fonctionnel (dès qu'il y a du trafic HTTP) |
| `geo_threat_intel.json` | Honeypot — Geo & Threat Intel | ⏳ carte + géo : nécessite GeoIP + IP publiques |

### Global
Trafic global / heure, trafic par service / heure, top 10 IP sources,
`event_type` × protocole, compteurs (connexions, interactions, IP distinctes),
sévérité des classifications.

### SSH
Top mots de passe, top usernames, méthodes d'auth, profil bot/human, top
commandes, top enchaînements (fingerprint de session), connexions, sessions →
escalade de privilèges, interactions moyennes / session.

### FTP
Top credentials (usernames / mots de passe), commandes FTP, dossiers et fichiers
les plus accédés, path traversal, connexions, uploads, sévérité.

### HTTP
URLs les plus visitées, méthodes, user-agents, accès `.env` / fichiers
sensibles, tentatives webshell / scan.

### Geo & Threat Intel
**Carte mondiale** (geomap) des IP sources, top pays, top ASN/fournisseurs,
réputation des IP (AbuseIPDB).

## Carte GeoIP et enrichissement — pré-requis data

OpenObserve construit le schéma du stream à partir des events réellement ingérés
et **renvoie une erreur sur toute colonne jamais vue**. La carte et les panneaux
géo se remplissent donc seulement quand l'enrichissement produit des coordonnées :

1. Déposer les bases MaxMind GeoLite2 dans `./data/geoip/`
   (`GeoLite2-City.mmdb` pour pays/ville/lat/lon, `GeoLite2-ASN.mmdb` pour l'ASN).
2. Recevoir du trafic depuis des **IP publiques** (les IP privées de test ne sont
   pas géolocalisables → `latitude`/`longitude` à `null`, ignorées par la carte).
3. Optionnel : `ABUSEIPDB_API_KEY` / `GREYNOISE_API_KEY` dans `.env` pour la
   réputation et la classification scanner.

> `Nombre de Mo de logs` : pas un panneau ; visible dans
> **OpenObserve → Streams** (`storage_size` du stream `honeypot_events`).

## Pipeline & schéma des données

`honeypots → JSONL bruts → analyzer (enrichissement) → enriched/events.jsonl →
Fluent Bit → OpenObserve`. L'analyzer ajoute le bloc `enrichment` +
`classification.profile`. Fluent Bit aplatit les objets imbriqués en colonnes
`_` : `payload.command` → `payload_command`, `classification.severity` →
`classification_severity`, `enrichment.latitude` → `enrichment_latitude`.
Stream cible : `honeypot_events`.

## Édition

Format dashboard OpenObserve **v3** : filtres = tableau vide, requêtes SQL
custom, colonnes mappées par alias (`x_axis_*` / `y_axis_*`, et
`latitude` / `longitude` / `weight` pour la geomap). Éditer dans l'UI puis
réexporter, ou modifier le JSON puis relancer `provision.py`.
