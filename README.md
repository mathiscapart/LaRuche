# LaRuche

**LaRuche** is a modular honeypot platform designed for security research, threat intelligence, and educational purposes. It provides SSH, FTP, and HTTP honeypots, along with a comprehensive analysis pipeline and a validation attack toolkit to ensure the honeypots are functioning correctly.

## Features

- **Multi-protocol Honeypots**: SSH, FTP, and HTTP honeypots with realistic decoys and weak credentials.
- **Attacker Module**: A validation toolkit to simulate realistic attacks and verify honeypot functionality.
- **Analysis Pipeline**: Enriches logs with GeoIP, AbuseIPDB, and GreyNoise data, and classifies attacker behavior.
- **Centralized Logging**: Fluent Bit collects and forwards logs to OpenObserve for visualization and analysis.
- **Dashboards**: Pre-configured OpenObserve dashboards for monitoring and threat intelligence.
- **Realistic Emulation**: An Apache reverse proxy fronts the HTTP honeypot, serving the real WordPress static assets and authentic Apache headers/error pages so the deception is hard to fingerprint.

## Architecture

```mermaid
graph TD
    A[Attacker / Internet] -->|HTTP| P[Apache reverse proxy]
    A -->|SSH / FTP| H[SSH and FTP honeypots]
    P -->|real static WP assets| A
    P -->|dynamic requests| W[HTTP honeypot - WordPress]
    H -->|JSON logs| C[Analyzer]
    W -->|JSON logs| C
    C -->|enriched events| D[Fluent Bit]
    D --> E[OpenObserve]
    E --> F[Dashboards]
```

Public HTTP traffic enters through the **Apache reverse proxy** (the only exposed
HTTP surface); the HTTP honeypot itself runs internally. SSH and FTP honeypots are
exposed directly. All honeypots write JSON events to a shared volume that the
analyzer enriches before Fluent Bit forwards them to OpenObserve.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.12+

### Running the Stack

1. Clone the repository:

```bash
git clone https://github.com/qualite863/LaRuche.git
cd LaRuche
```

2. Start the stack:

```bash
docker compose up -d
```

3. Access OpenObserve at `http://localhost:5080` with the default credentials:
   - Username: `admin@laruche.local`
   - Password: `Honeypot2026!`

### Running the Attacker

The `attacker` module is used to validate the honeypots by simulating attacks. It can be run directly or via Docker Compose:

```bash
# Check dependencies
docker compose run --rm attacker check --for all

# Run SSH attack
docker compose run --rm attacker ssh --target 10.13.0.10

# Run FTP attack
docker compose run --rm attacker ftp --target 10.13.0.10

# Run HTTP attack
docker compose run --rm attacker http --target target.example.com

# Run all attacks (nmap discovery, then attack every detected service)
docker compose run --rm attacker all --target 10.13.0.10 --parallel
```

## Components

### Honeypots

- **SSH Honeypot**: Listens on ports 22 and 2222, accepts weak credentials, and logs all interactions.
- **FTP Honeypot**: Listens on ports 21 and 2121, supports anonymous login, and logs all interactions.
- **HTTP Honeypot**: Emulates a WordPress 6.5.2 site — fake `wp-login`/`wp-admin` with credential capture, REST API, dynamic `phpinfo`, phpMyAdmin, exploit/scanner detection and a `.env` canary. It runs **internally**, fronted by the Apache reverse proxy (see below).

### Reverse Proxy (Apache)

The `honeypot-proxy` service is a real **Apache 2.4.57 (Debian)** in front of the HTTP honeypot — it is the only public HTTP surface (ports 80 and 8080) and makes the deception much harder to detect:

- Serves the **real WordPress 6.5.2 static assets** from disk (`wp-includes`, `wp-content`, `wp-admin/{css,js,images}`, `readme.html`, `license.txt`), so they return authentic `ETag` / `Last-Modified` / `Accept-Ranges` headers and byte-exact content.
- Emits genuine Apache headers, version string and error pages (with the `Server at … Port 80` footer).
- Reverse-proxies every dynamic request to the internal HTTP honeypot (FastAPI).

## Attacker

`attacker` is the offensive brick (M1SPRO **B10**): it points realistic attacks
at the honeypots to verify they accept the right credentials, serve the right
decoys, and that the whole detection/logging chain actually records the
activity. It is a **validation tool, not a weapon** — it is non-destructive, and
every campaign also flags when the target *looks like a honeypot*.

Available commands: `check` (dependency pre-flight), `ssh`, `ftp`, `http`, and
`all` (nmap discovery, then attack every detected service).

> Wordlists (SecLists default credentials, passwords, usernames, directories)
> are **downloaded automatically** by the script on first use, then cached in
> `attacker/wordlists/`. No manual download is required.

Detailed documentation: [`docs/ATTACKER.md`](docs/ATTACKER.md).

### Running the attacker

Point `--target` at the host you want to attack — an IP or a hostname:

```bash
docker compose run --rm attacker ssh  --target 10.13.0.10
docker compose run --rm attacker ftp  --target 10.13.0.10
docker compose run --rm attacker http --target target.example.com

# nmap discovery, then attack every detected service (in parallel)
docker compose run --rm attacker all  --target 10.13.0.10 --parallel

# Check dependencies (binaries, payloads, connectivity)
docker compose run --rm attacker check --for all
```

By default the SSH/FTP brute-force tries the service's default credentials
first; add `--full-wordlist` to go straight to the large wordlist. See
[`docs/ATTACKER.md`](docs/ATTACKER.md) for all options.


### Analyzer

The `analyzer` module enriches logs with additional context:

- **GeoIP**: Adds country, city, and ASN information using MaxMind GeoLite2 databases.
- **AbuseIPDB**: Adds abuse scores for IP addresses.
- **GreyNoise**: Classifies IPs as malicious, benign, or unknown.
- **Behavioral Profiling**: Classifies attackers as bots, bruteforcers, humans, or scanners.

### Fluent Bit

Fluent Bit collects logs from the honeypots and forwards them to OpenObserve. It is configured to:

- Read JSON logs from a shared volume.
- Parse and forward logs to OpenObserve.
- Provide health and metrics endpoints.

### OpenObserve

OpenObserve is used for log storage, visualization, and threat intelligence. It includes:

- **Dashboards**: Pre-configured dashboards for monitoring SSH, FTP, HTTP, and global traffic.
- **Geo & Threat Intel**: Maps IP addresses and provides threat intelligence data.

For detailed documentation, see [`docs/OPEN-OBSERVE.md`](docs/OPEN-OBSERVE.md).

## Configuration

### Environment Variables

The stack can be configured using environment variables:

- `OPENOBSERVE_USER`: OpenObserve username (default: `admin@laruche.local`).
- `OPENOBSERVE_PASSWORD`: OpenObserve password (default: `Honeypot2026!`).
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key (optional).
- `GREYNOISE_API_KEY`: GreyNoise API key (optional).

### GeoIP Databases

To enable GeoIP enrichment, download the MaxMind GeoLite2 databases and place them in `data/geoip/`:

- `GeoLite2-City.mmdb`
- `GeoLite2-ASN.mmdb`

You can download these databases from the [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) repository, which provides up-to-date versions of the GeoLite2 databases.

## Documentation

- **[Attacker Documentation](docs/ATTACKER.md)**: Detailed documentation for the attacker module, including how it works, requirements, commands, and usage examples.
- **[OpenObserve Documentation](docs/OPEN-OBSERVE.md)**: Detailed documentation for OpenObserve dashboards, including import instructions, dashboard descriptions, and configuration.
- **[Honeypots Documentation](docs/HONEYPOTS.md)**: Detailed documentation for the SSH, FTP, and HTTP honeypots, including configuration, features, and usage examples.
- **[Analyzer Documentation](docs/ANALYZER.md)**: Detailed documentation for the analyzer module, including enrichment, classification, and configuration.
- **[Fluent Bit Documentation](docs/FLUENT-BIT.md)**: Detailed documentation for the Fluent Bit log collector, including configuration, inputs, outputs, and usage examples.
- **[Event Schema](docs/event.schema.json)**: JSON schema for honeypot events, defining the structure and properties of the events generated by the honeypots.

## CI/CD and Releases

LaRuche uses GitHub Actions for continuous integration and semantic-release for automated version management.

### CI Pipeline

The CI pipeline includes:
- **Linting**: Code quality checks with Ruff and Bandit
- **Testing**: Comprehensive test suite with pytest
- **Building**: Docker image building for all components
- **Scanning**: Vulnerability scanning with Trivy
- **Release**: Automatic version management and changelog generation

### Semantic Release

LaRuche follows [Conventional Commits](https://www.conventionalcommits.org/) for commit messages. Based on your commit messages, semantic-release will:

- **Automatically determine the next version** (patch, minor, or major)
- **Generate a changelog** from commit messages
- **Create GitHub releases** with release notes
- **Update the version** in package files

#### Commit Message Format

```bash
# Major version (breaking changes)
feat(api): add new endpoint (BREAKING CHANGE)

# Minor version (new features)
feat(ssh): add malware detection capability

# Patch version (bug fixes)
fix(ftp): correct authentication logic bug

# No release (documentation, refactoring, etc.)
chore: update README
docs: add API documentation
style: format code with black
refactor: improve detection module structure
```

### Release Process

1. Push commits to `main` or `prod` branches
2. CI runs tests and builds
3. If all checks pass, semantic-release determines the version bump
4. A new GitHub release is created with automated changelog
5. Version tags are created in the format `vX.Y.Z`

## Acknowledgements

- **SecLists**: For providing wordlists used in the attacker module.
- **MaxMind**: For providing GeoLite2 databases for GeoIP enrichment.
- **OpenObserve**: For providing a powerful log storage and visualization platform.
- **Semantic Release**: For automating version management and releases.

## Disclaimer

This project is designed for educational and research purposes only. Do not use it to attack systems without explicit permission.
