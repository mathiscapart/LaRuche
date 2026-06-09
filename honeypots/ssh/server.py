"""Honeypot SSH — serveur asyncssh (EPIC-1).

Capture toutes les tentatives d'authentification (US-01), n'accepte qu'une
liste de comptes faibles non-root avec tarpit sur échec (US-03), puis présente
un faux shell Debian 12 (US-02) instrumenté pour la détection d'escalade
(US-04), de malware (US-05), le profilage bot/human (US-06) et le fingerprint
de session (US-07).

Aucune dépendance réseau au démarrage : les événements sont écrits en JSON
Lines (stdout + fichier) pour être collectés par Filebeat vers le SIEM.
"""

from __future__ import annotations

import asyncio
import functools
import random
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field

import asyncssh
from commands import ShellState, run_command
from config import Config, load_config
from detection import SessionProfiler, classify_command, is_escalation
from events import EventSink, build_event

# Version annoncée : OpenSSH Debian plausible plutôt que la bannière asyncssh
# (réduit le fingerprinting trivial du honeypot).
SERVER_VERSION = "OpenSSH_9.2p1 Debian-2+deb12u2"

# Commandes qui, sur un vrai serveur, impliquent du réseau/IO et donc une
# latence sensible et variable. Les autres répondent quasi instantanément :
# une latence *uniforme* sur toutes les commandes serait elle-même un tell.
_SLOW_COMMANDS = {
    "wget", "curl", "apt", "apt-get", "ping", "nmap", "git", "docker",
    "pip", "pip3", "nslookup", "dig", "host", "scp", "ssh", "systemctl",
}


def _response_latency(line: str, config: Config) -> float:
    """Latence de réponse simulée en secondes.

    Petite et variable par défaut (round-trip réaliste), nettement plus longue
    et irrégulière pour les commandes réseau/IO — pour casser toute signature
    de délai constant tout en restant crédible.
    """
    base = random.uniform(config.jitter_ms_min, config.jitter_ms_max) / 1000  # noqa: S311
    cmd = line.split()[0] if line.split() else ""
    if cmd in _SLOW_COMMANDS:
        return base + random.uniform(0.12, 0.85)  # noqa: S311
    return base

# Corrèle les événements d'auth (côté SSHServer) avec la session shell
# (côté process_factory), par adresse (host, port) — unique par connexion TCP.
_REGISTRY: dict[tuple[str, int], SessionRecord] = {}


@dataclass
class SessionRecord:
    """État partagé d'une connexion entre l'auth et le shell."""

    session_id: str
    src_ip: str
    src_port: int
    started_at: float
    hostname: str
    username: str = ""
    authenticated: bool = False
    shell: ShellState = field(default_factory=ShellState)
    profiler: SessionProfiler = field(default_factory=SessionProfiler)
    summary_emitted: bool = False


class HoneypotServer(asyncssh.SSHServer):
    """Une instance par connexion : capture connexion + tentatives d'auth."""

    def __init__(self, config: Config, sink: EventSink) -> None:
        self._config = config
        self._sink = sink
        self._record: SessionRecord | None = None

    # --- cycle de vie de la connexion ------------------------------------
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        host, port = peer[0], peer[1]
        record = SessionRecord(
            session_id=str(uuid.uuid4()),
            src_ip=host,
            src_port=port,
            started_at=time.monotonic(),
            hostname=self._config.hostname,
        )
        record.shell.hostname = self._config.hostname
        self._record = record
        _REGISTRY[(host, port)] = record
        self._emit(record, "connection", {})

    def connection_lost(self, exc: Exception | None) -> None:
        record = self._record
        if record is None:
            return
        self._emit_session_summary(record)
        _REGISTRY.pop((record.src_ip, record.src_port), None)

    # --- authentification (US-01, US-03) ---------------------------------
    def begin_auth(self, username: str) -> bool:
        # True => authentification requise (on veut capturer les credentials).
        if self._record is not None:
            self._record.username = username
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        record = self._record
        if record is not None:
            self._emit(
                record,
                "auth_attempt",
                {"username": username, "password": password, "auth_method": "password"},
            )
        if self._config.is_allowed(username, password):
            if record is not None:
                record.authenticated = True
                record.username = username
                record.shell.user = username
                record.shell.cwd = f"/home/{username}"
                self._emit(
                    record,
                    "auth_success",
                    {"username": username, "password": password, "auth_method": "password"},
                )
            return True
        # US-03 : tarpit sur chaque tentative refusée. Jitteré autour de la
        # valeur configurée : un délai *fixe* serait lui-même une signature de
        # honeypot (le vrai OpenSSH varie autour de ~2,5s).
        delay = self._config.tarpit_seconds * random.uniform(0.82, 1.18)  # noqa: S311
        await asyncio.sleep(delay)
        return False

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        # On capture le fingerprint (US-01) puis on refuse, l'attaquant
        # bascule alors sur le mot de passe.
        record = self._record
        if record is not None:
            self._emit(
                record,
                "auth_attempt",
                {
                    "username": username,
                    "auth_method": "publickey",
                    "key_fingerprint": key.get_fingerprint(),
                },
            )
        return False

    # --- helpers d'émission ----------------------------------------------
    def _emit(self, record: SessionRecord, event_type: str, payload: dict) -> None:
        self._sink.emit(
            build_event(
                event_type=event_type,
                src_ip=record.src_ip,
                src_port=record.src_port,
                session_id=record.session_id,
                payload=payload,
                honeypot_host=record.hostname,
            )
        )

    def _emit_session_summary(self, record: SessionRecord) -> None:
        if record.summary_emitted:
            return
        record.summary_emitted = True
        duration_ms = int((time.monotonic() - record.started_at) * 1000)
        self._sink.emit(
            build_event(
                event_type="disconnection",
                src_ip=record.src_ip,
                src_port=record.src_port,
                session_id=record.session_id,
                payload={
                    "command_count": len(record.profiler.commands),
                    "commands": record.profiler.commands,
                    "session_fingerprint": record.profiler.fingerprint(),
                    "duration_ms": duration_ms,
                },
                classification=record.profiler.session_classification(),
                honeypot_host=record.hostname,
            )
        )


async def _handle_command(
    record: SessionRecord, raw_line: str, config: Config, sink: EventSink
) -> tuple[str, bool]:
    """Traite une commande : journalise, applique le jitter, calcule la sortie.

    Renvoie ``(sortie, should_exit)``. Utilisé en mode interactif et en exec.
    """
    line = raw_line.strip()
    record.profiler.record(line, time.monotonic())

    # US-02 : latence réaliste par commande (anti-timing fingerprint).
    await asyncio.sleep(_response_latency(line, config))

    tokens = line.split()
    cmd = tokens[0] if tokens else ""
    should_exit = cmd in ("exit", "logout")

    classification = classify_command(line)
    payload: dict = {"command": line}
    escalating = is_escalation(line)
    if escalating:
        payload["target_user"] = "root"

    sink.emit(
        build_event(
            event_type="command",
            src_ip=record.src_ip,
            src_port=record.src_port,
            session_id=record.session_id,
            payload=payload,
            classification=classification,
            honeypot_host=record.hostname,
        )
    )

    # US-04 : escalade réussie → la session passe en root (prompt #, whoami root).
    if escalating:
        record.shell.escalate_to_root()
        return "", should_exit

    # US-04 : changement de mot de passe simulé (direct ou via sudo).
    if tokens[:1] == ["passwd"] or tokens[:2] == ["sudo", "passwd"]:
        return "passwd: password updated successfully", should_exit

    # `sudo`, `cd`, etc. sont gérés dans l'émulateur (commands.py).
    return run_command(record.shell, line), should_exit


def _login_banner(record: SessionRecord) -> str:
    return (
        "Linux prod-srv-01 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC "
        "Debian 6.1.90-1 (2024-05-03) x86_64\n\n"
        "The programs included with the Debian GNU/Linux system are free software;\n"
        "the exact distribution terms for each program are described in the\n"
        "individual files in /usr/share/doc/*/copyright.\n\n"
        "Last login: Mon Jun  9 09:02:14 2026 from 10.0.2.2\n"
    )


async def handle_shell(
    process: asyncssh.SSHServerProcess, config: Config, sink: EventSink
) -> None:
    """Boucle du faux shell (mode interactif) ou exécution unique (mode exec)."""
    peer = process.get_extra_info("peername")
    record = _REGISTRY.get((peer[0], peer[1]))
    if record is None:  # connexion non corrélée (cas limite) : on en crée une.
        record = SessionRecord(
            session_id=str(uuid.uuid4()),
            src_ip=peer[0],
            src_port=peer[1],
            started_at=time.monotonic(),
            hostname=config.hostname,
        )

    username = process.get_extra_info("username") or record.username
    if username:
        record.shell.user = username
        if not record.shell.is_root:
            record.shell.cwd = f"/home/{username}"

    try:
        # Mode exec : `ssh user@host 'cmd'` — non interactif, signal fort de bot.
        if process.command is not None:
            record.profiler.interactive = False
            output, _ = await _handle_command(record, process.command, config, sink)
            if output:
                process.stdout.write(output + "\n")
            process.exit(0)
            return

        # Mode interactif.
        process.stdout.write(_login_banner(record))
        while not process.stdin.at_eof():
            process.stdout.write(record.shell.prompt())
            try:
                line = await process.stdin.readline()
            except asyncssh.BreakReceived:
                break
            if not line:
                break
            line = line.rstrip("\n")
            if not line.strip():
                continue
            output, should_exit = await _handle_command(record, line, config, sink)
            if output:
                process.stdout.write(output + "\n")
            if should_exit:
                process.stdout.write("logout\n")
                break
        process.exit(0)
    except (asyncssh.ConnectionLost, BrokenPipeError):
        pass


async def start_server(config: Config, sink: EventSink) -> asyncssh.SSHAcceptor:
    """Démarre le serveur SSH et renvoie l'acceptor (déjà en écoute)."""
    # Clés d'hôte générées en mémoire : rien sur le disque à fingerprinter.
    host_keys = [
        asyncssh.generate_private_key("ssh-ed25519"),
        asyncssh.generate_private_key("ssh-rsa", key_size=3072),
    ]

    def server_factory() -> HoneypotServer:
        return HoneypotServer(config, sink)

    return await asyncssh.create_server(
        server_factory,
        host=config.bind_host,
        port=config.bind_port,
        server_host_keys=host_keys,
        server_version=SERVER_VERSION,
        process_factory=functools.partial(handle_shell, config=config, sink=sink),
    )


async def main() -> None:
    config = load_config()
    sink = EventSink(config.log_file)

    print(
        f"[ssh-honeypot] écoute sur {config.bind_host}:{config.bind_port} "
        f"(hostname simulé: {config.hostname})",
        file=sys.stderr,
    )

    acceptor = await start_server(config, sink)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover - plateformes sans signaux
            pass

    try:
        await stop.wait()
    finally:
        acceptor.close()
        sink.close()
        print("[ssh-honeypot] arrêt", file=sys.stderr)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncssh.Error) as exc:  # pragma: no cover
        print(f"[ssh-honeypot] erreur fatale: {exc}", file=sys.stderr)
        sys.exit(1)
