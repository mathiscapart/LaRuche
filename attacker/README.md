# attacker — Honeypot validation attack toolkit

`attacker` is the offensive brick (M1SPRO **B10**) of the LaRuche honeypot
platform. It points realistic, opportunistic attacks at the SSH / FTP / HTTP
honeypots so you can prove they accept the right logins, serve the right decoys,
and — crucially — that the whole detection/logging chain downstream actually
records the activity.

It is a **validation tool, not a weapon**: every campaign is wired to flag when a
target *looks like a honeypot* (so you don't keep feeding telemetry to a trap by
accident), and nothing it does is destructive — it only sends requests a real
scanner would.

---

## Table of contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Credential strategy (default-first)](#credential-strategy-default-first)
- [Honeypot self-detection](#honeypot-self-detection)
- [Wordlists](#wordlists)
- [Reports & artefacts](#reports--artefacts)
- [Running with Docker Compose](#running-with-docker-compose)
- [Development](#development)
- [Module layout](#module-layout)

---

## How it works

Each protocol campaign runs as an ordered pipeline where every phase feeds the
next instead of firing in isolation:

```
        ┌─────────────┐
  all → │ nmap recon  │ → discovers open services + maps them to a campaign
        └──────┬──────┘
               ▼
   ┌───────────────────────┐   ┌───────────────────────┐   ┌──────────────┐
   │ ssh                   │   │ ftp                   │   │ http         │
   │  • banner detection   │   │  • banner detection   │   │ 1 fingerprint│
   │  • default-cred hydra │   │  • default-cred hydra │   │ 2 nikto      │
   │  • (opt) full wordlist│   │  • anonymous login    │   │ 3 dirsearch  │
   │                       │   │  • (opt) full wordlist│   │ 4 attack     │
   └───────────┬───────────┘   └───────────┬───────────┘   └──────┬───────┘
               └───────────────────────────┴──────────────────────┘
                                     ▼
                       honeypot self-detection verdict
                       (+ optional log assertions)
```

For HTTP the fingerprint decides the rest: a recognised CMS (WordPress, Joomla,
Drupal, Magento, PrestaShop, TYPO3) gets CMS-aware login + recon vectors;
anything else gets a generic discovery + credential spray. Discovery results
(dirsearch) are handed to the attack phase so the spray hits the real surface.

---

## Requirements

The Python package itself is **dependency-free** (standard library only; runs on
Python ≥ 3.12, the container ships 3.14). The attacks shell out to standard
offensive binaries:

| Binary      | Used for                       | Required for          |
|-------------|--------------------------------|-----------------------|
| `hydra`     | SSH / FTP brute-force          | `ssh`, `ftp`          |
| `nmap`      | service discovery              | `all`                 |
| `nikto`     | HTTP vulnerability scan        | `http` (optional)     |
| `dirsearch` | HTTP content discovery         | `http` (optional)     |

Run `attacker check` to verify everything is in place before a campaign. The
provided `Dockerfile` already bundles all four tools.

---

## Quick start

```bash
# From the repo root, with the package importable (or inside the container):
python -m attacker check --for all          # pre-flight: binaries, payloads, network
python -m attacker ssh  --target 10.13.0.10 # SSH brute-force
python -m attacker ftp  --target 10.13.0.10 # FTP brute-force + anonymous
python -m attacker http --target 10.13.0.10 # full HTTP scan pipeline
python -m attacker all  --target 10.13.0.10 # nmap discovery, then every service
```

Ports are auto-discovered when `--port` is omitted (SSH tries `22` then `2222`,
FTP `21`/`2121`, HTTP `80`/`8080`).

---

## Commands

All commands share the [global options](#global-options) below.

### `check` — dependency pre-flight

```bash
python -m attacker check --for all        # check | http | ftp | ssh | all
python -m attacker check --for ssh --no-network
```

Reports Python version, required/optional binaries, payload files, and TCP
reachability of the target. Exit code `1` if a blocking dependency is missing.

### `ssh` — SSH brute-force

```bash
python -m attacker ssh --target HOST [--port 2222]
```

| Option                  | Default | Description                                            |
|-------------------------|---------|--------------------------------------------------------|
| `--port`                | auto    | SSH port (auto-discovers 22 → 2222)                    |
| `--hydra-tasks`         | 16      | parallel hydra tasks                                   |
| `--hydra-timeout`       | 120     | seconds before hydra is killed (`0` = run to the end)  |
| `--default-credentials` | SecLists| `user:password` list for the default-credential phase  |
| `--full-wordlist`       | off     | skip defaults, brute-force with the large wordlist     |
| `--password-wordlist`   | auto    | override the large password list                       |
| `--username-wordlist`   | auto    | override the large username list                       |
| `--skip-hydra`          | off     | skip the brute-force phase entirely                    |

### `ftp` — FTP brute-force

```bash
python -m attacker ftp --target HOST [--port 2121]
```

Same credential options as `ssh`, plus:

| Option              | Default | Description                              |
|---------------------|---------|------------------------------------------|
| `--skip-anonymous`  | off     | skip the anonymous-login probe           |
| `--hydra-timeout`   | 300     | seconds before hydra is killed           |

### `http` — HTTP scan pipeline

```bash
python -m attacker http --target HOST [--port 8080]
```

| Option                 | Default | Description                                |
|------------------------|---------|--------------------------------------------|
| `--nikto-timeout`      | 120     | nikto wall-clock budget                    |
| `--dirsearch-wordlist` | auto    | content-discovery wordlist                 |
| `--max-login-attempts` | 40      | cap on credential-spray attempts           |
| `--skip-nikto`         | off     | skip phase 2                               |
| `--skip-dirsearch`     | off     | skip phase 3                               |
| `--skip-login`         | off     | skip phase 4 (login/recon attacks)         |
| `--password-wordlist`  | auto    | override the password list                 |
| `--username-wordlist`  | auto    | override the username list                 |

### `all` — discover, then attack everything

```bash
python -m attacker all --target HOST [--parallel]
```

Runs an `nmap` service scan and launches a campaign per detected service.

| Option                          | Default        | Description                                       |
|---------------------------------|----------------|---------------------------------------------------|
| `--ports`                       | common+lab set | nmap port spec for discovery                      |
| `--nmap-timeout`                | 120            | seconds before the discovery scan is aborted      |
| `--http-port` / `--ftp-port` / `--ssh-port` | —  | force a campaign on this port even if nmap misses |
| `--skip-http` / `--skip-ftp` / `--skip-ssh` | off | skip a whole category                             |
| `--parallel`                    | off            | run the discovered campaigns concurrently         |

### Global options

| Option              | Description                                              |
|---------------------|----------------------------------------------------------|
| `--target`          | target IP (default `127.0.0.1`)                          |
| `--reports-dir DIR` | output directory for artefacts                          |
| `--no-color`        | disable ANSI colours (also honours `NO_COLOR`)          |
| `-v` / `--verbose`  | increase verbosity (`-v` = debug)                       |
| `-q` / `--quiet`    | warnings and above only                                 |
| `--skip-dep-check`  | skip the dependency pre-flight                          |
| `--version`         | print version and exit                                  |

---

## Credential strategy (default-first)

SSH and FTP brute-force in two stages, optimised for signal over noise:

1. **Default credentials first.** By default hydra is fed the service's *known
   default* `user:password` pairs (SecLists `ssh-/ftp-betterdefaultpasslist`,
   already in hydra's `-C` combo format). Fast, high-signal, and exactly what an
   out-of-the-box honeypot tends to accept.
2. **Escalate to the large wordlist only if needed.** If no default credential
   works, you are **warned** and prompted to fall back to the big cross-product
   wordlist (slow & noisy). On a non-interactive session (the usual
   `docker compose run` case) the escalation is declined automatically.

Force the large wordlist straight away with `--full-wordlist`. Provide your own
combo list with `--default-credentials FILE`.

```bash
# defaults only (prompted to escalate if nothing matches)
python -m attacker ssh --target HOST

# go straight to the large wordlist
python -m attacker ssh --target HOST --full-wordlist
```

---

## Honeypot self-detection

Detection is woven *into* the attack, so it costs no extra brute-force pass.
Each campaign accumulates weighted signals and, above a confidence threshold,
prints a prominent `HONEYPOT WARNING` (it never blocks the attack):

- **Banner / body signatures** — known honeypot fingerprints (Cowrie, Kippo,
  Dionaea, Glastopf, SNARE/Tanner, Conpot, …) plus a catch-all HTTP probe.
- **Credential shape** — reuses the brute-force result: one user accepted with
  several passwords, an implausibly large haul, or **multiple known-default
  credentials** all point at a credential-harvesting trap.

---

## Wordlists

Wordlists live in `attacker/wordlists/` and are **fetched on demand** the first
time they are needed, then cached. They come from the **SecLists** project
([danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)),
downloaded from the `master` branch over `raw.githubusercontent.com`:

| Local file                    | Source path in [SecLists](https://github.com/danielmiessler/SecLists) |
|-------------------------------|-----------------------------------------------------------------------|
| `ssh-default-credentials.txt` | `Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt`         |
| `ftp-default-credentials.txt` | `Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt`         |
| `http-default-passwords.txt`  | `Passwords/Default-Credentials/default-passwords.txt`                 |
| `passwords.txt`               | `Passwords/Common-Credentials/Pwdb_top-10000.txt`                     |
| `usernames.txt`               | `Usernames/top-usernames-shortlist.txt`                               |
| `directories.txt`             | `Discovery/Web-Content/common.txt`                                    |

The exact URLs are defined in [`wordlists.py`](wordlists.py). Override any list
with the matching `--*-wordlist` / `--default-credentials` flag. For a heavier
password list you can drop in `rockyou.txt` and pass it via `--password-wordlist`.

---

## Reports & artefacts

Every run writes a timestamped directory under `--reports-dir` (default
`attacker/reports/`) containing the raw tool logs plus a professional
**assessment report** in two formats:

- **`report.md`** — a human-readable Markdown report: status banner + risk
  rating, executive summary, key metrics, honeypot assessment, compromised
  credentials, a severity-ranked findings table, the per-phase breakdown and an
  artefact index.
- **`report.json`** — the same data, machine-readable, for the analyzer or CI.

```
reports/
  ssh-20260611-101500/
    hydra-default.log         # default-credential phase
    hydra-results-default.txt
    hydra-full.log            # only if escalated / --full-wordlist
    report.md
    report.json
  all-20260611-101500/
    recon-.../nmap.log
    ssh-.../report.md         # one report per discovered service
    report.md                 # consolidated campaign report
    report.json
```

The report's **risk rating** is `Critical` whenever credentials are cracked,
otherwise it tracks the highest-severity finding. A honeypot-suspected target is
flagged prominently and downgrades the credibility of any "success".

---

## Running with Docker Compose

The `attacker` service is defined in the repo's `compose.yml`. Point `--target`
at the host you want to attack — an IP or a hostname:

```bash
docker compose run --rm attacker ssh  --target 10.13.0.10
docker compose run --rm attacker ftp  --target 10.13.0.10
docker compose run --rm attacker http --target target.example.com
docker compose run --rm attacker all  --target 10.13.0.10 --parallel
```

The image bundles `hydra`, `nmap`, `nikto` and `dirsearch`; the entrypoint is
`python -m attacker`.

---

## Development

```bash
# run the unit-test suite (no network / no real subprocess required)
python -m pytest attacker/tests/ -q

# lint (config in ruff.toml at the repo root)
ruff check attacker/
```

Tests are pure-logic and fully mocked — they exercise the parsers, scoring,
credential orchestration and CLI without touching the network.

---

## Module layout

```
attacker/
  main.py              # CLI: argument parsing, command handlers, `all` orchestration
  __main__.py          # `python -m attacker` entry point
  config.py            # paths, payload loaders
  deps.py              # dependency pre-flight (binaries, payloads, network)
  wordlists.py         # on-demand SecLists download + cache
  logging.py           # coloured logging setup
  recon/
    port_scan.py       # nmap service discovery (greppable parser)
  attacks/
    common.py          # HTTP client, hydra runner, credential bruteforce, ResultsDir
    honeypot.py        # honeypot self-detection (banners + credential shape)
    ssh_bruteforce.py  # SSH campaign
    ftp_bruteforce.py  # FTP campaign (+ anonymous)
    http_scan.py       # HTTP pipeline (fingerprint → nikto → dirsearch → attack)
    web_fingerprint.py # CMS / technology fingerprinting
    web_attacks.py     # CMS-aware & generic login/recon attacks
  payloads/            # HTTP probe paths & injection payloads
  wordlists/           # cached wordlists (downloaded on demand)
  reports/             # run artefacts (gitignored)
  tests/               # unit tests
```
