# LaRuche

Honeypot platform (SSH / FTP / HTTP) with analysis and a validation attack
brick.

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

Detailed documentation: [`attacker/README.md`](attacker/README.md).

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
[`attacker/README.md`](attacker/README.md) for all options.
