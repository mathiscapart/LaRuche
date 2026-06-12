"""Honeypot FTP — serveur pyftpdlib (EPIC-1).

Présente une arborescence factice en lecture seule (dossiers leurres
``/backup``, ``/conf``, ``/exports`` — cf. ``filesystem.py``) et journalise
toute la reconnaissance (LIST / CWD / PWD / NLST / ...) ainsi que les
tentatives d'authentification et de téléchargement, en JSON Lines (stdout +
fichier), exactement comme le honeypot SSH.

pyftpdlib confine chaque session à la racine leurre : un attaquant ne peut ni
remonter (``..``) ni atteindre le vrai filesystem du conteneur. Les commandes
LIST / CWD / PWD sont donc gérées nativement par la lib, sur du contenu forgé.

Aucune dépendance réseau au démarrage : les événements sont écrits localement
pour être collectés par Filebeat vers le SIEM (Wazuh).
"""

from __future__ import annotations

import os
import signal
import sys
import time
import uuid

from config import Config, load_config
from detection import (
    SessionProfiler,
    classify_command,
    classify_credential_reuse,
    classify_download,
)
from events import EventSink, build_event
from filesystem import is_canary, materialize
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Commandes d'authentification : journalisées via les callbacks on_login* (avec
# le couple identifiant/mot de passe), jamais comme événement "command" — on
# évite ainsi de noyer/dupliquer les credentials dans les commandes.
_AUTH_COMMANDS = {"USER", "PASS"}


class LoggingFTPHandler(FTPHandler):
    """Une instance par connexion : émet un événement par action de l'attaquant.

    Les attributs partagés (sink d'événements, hostname simulé) sont injectés au
    niveau de la classe par ``build_server`` avant le démarrage du serveur.
    """

    # Injectés avant le run (une seule instance de sink pour tout le process).
    event_sink: EventSink | None = None
    honeypot_host: str = "prod-srv-01"
    config: Config | None = None

    # --- cycle de vie de la connexion ------------------------------------
    def on_connect(self) -> None:
        self._session_id = str(uuid.uuid4())
        self._started = time.monotonic()
        self._profiler = SessionProfiler()
        self._summary_emitted = False
        self._emit("connection", {})

    def on_disconnect(self) -> None:
        profiler = getattr(self, "_profiler", None)
        if profiler is None or getattr(self, "_summary_emitted", False):
            return
        self._summary_emitted = True
        duration_ms = int((time.monotonic() - getattr(self, "_started", time.monotonic())) * 1000)
        self._emit(
            "disconnection",
            {
                "command_count": len(profiler.commands),
                "commands": profiler.commands,
                "session_fingerprint": profiler.fingerprint(),
                "duration_ms": duration_ms,
            },
            profiler.session_classification(),
        )

    # --- authentification -------------------------------------------------
    def on_login(self, username: str) -> None:
        creds = {"username": username, "password": self.password, "auth_method": "password"}
        self._emit("auth_attempt", creds)
        # Login réussi avec des identifiants du honeypot SSH -> réutilisation de
        # creds inter-services (mouvement latéral) : on tague auth_success.
        cfg = self.config
        reuse = (
            cfg is not None
            and self.password is not None
            and cfg.is_ssh_credential(username, self.password)
        )
        self._emit("auth_success", creds, classify_credential_reuse() if reuse else None)

    def on_login_failed(self, username: str, password: str) -> None:
        self._emit(
            "auth_attempt",
            {"username": username, "password": password, "auth_method": "password"},
        )

    # --- transfert --------------------------------------------------------
    def on_file_sent(self, file: str) -> None:
        virtual = self.fs.fs2ftp(file) if self.fs is not None else file
        # Téléchargement d'un fichier canary -> exfiltration (CANARY_TRIGGERED).
        self._emit(
            "file_download",
            {"filename": os.path.basename(file), "path": virtual},
            classify_download(virtual, is_canary=is_canary(virtual)),
        )

    # --- capture de TOUTES les commandes (LIST / CWD / PWD / ...) ---------
    # On hooke pre_process_command : on y voit la ligne BRUTE telle que tapée
    # par l'attaquant (vue FTP, ex. « CWD /backup »), AVANT que pyftpdlib ne
    # convertisse le chemin FTP en chemin réel du conteneur. On ne fuite donc
    # jamais la racine leurre, et on capture aussi les commandes refusées
    # (chemin invalide, droits insuffisants) — précieux pour la reconnaissance.
    def pre_process_command(self, line, cmd, arg) -> None:
        if cmd.upper() not in _AUTH_COMMANDS:
            self._record_command(cmd, arg or "", line)
        super().pre_process_command(line, cmd, arg)

    def _record_command(self, cmd: str, arg: str, raw_line: str) -> None:
        line = raw_line.strip()
        profiler = getattr(self, "_profiler", None)
        if profiler is not None:
            profiler.record(line, time.monotonic())
        cwd = self.fs.cwd if self.fs is not None else "/"
        payload: dict = {"command": line}
        if arg:
            payload["path"] = arg
        self._emit("command", payload, classify_command(cmd, arg, cwd))

    # --- helper d'émission ------------------------------------------------
    def _emit(self, event_type: str, payload: dict, classification: dict | None = None) -> None:
        sink = self.event_sink
        if sink is None:  # pragma: no cover - sink toujours injecté en prod
            return
        try:
            src_port = int(self.remote_port)
        except (TypeError, ValueError):
            src_port = 0
        sink.emit(
            build_event(
                event_type=event_type,
                src_ip=self.remote_ip or "0.0.0.0",  # noqa: S104  # nosec B104
                src_port=src_port,
                session_id=getattr(self, "_session_id", "unknown"),
                payload=payload,
                classification=classification,
                honeypot_host=self.honeypot_host,
            )
        )


def build_authorizer(config: Config) -> DummyAuthorizer:
    """Construit l'autorisation : comptes faibles + creds SSH réutilisables +
    anonyme, tous en lecture seule.

    Permissions ``elr`` = changer de dossier (e), lister (l), récupérer (r) —
    aucune écriture. ``accepted_credentials`` inclut les identifiants du honeypot
    SSH pour capturer leur réutilisation. Les logins refusés passent par
    ``on_login_failed`` et sont donc tout de même capturés.
    """
    authorizer = DummyAuthorizer()
    for cred in config.accepted_credentials():
        try:
            authorizer.add_user(cred.username, cred.password, config.decoy_root, perm="elr")
        except ValueError:
            # username déjà enregistré : on conserve la première occurrence.
            pass
    if config.anonymous_enabled:
        authorizer.add_anonymous(config.decoy_root, perm="elr")
    return authorizer


def build_server(config: Config, sink: EventSink) -> FTPServer:
    """Matérialise l'arbre leurre, configure le handler et renvoie le serveur."""
    materialize(config.decoy_root)

    LoggingFTPHandler.authorizer = build_authorizer(config)
    LoggingFTPHandler.banner = config.banner
    LoggingFTPHandler.masquerade_address = config.masquerade_address
    LoggingFTPHandler.passive_ports = list(range(config.pasv_min, config.pasv_max + 1))
    LoggingFTPHandler.event_sink = sink
    LoggingFTPHandler.honeypot_host = config.hostname
    LoggingFTPHandler.config = config

    server = FTPServer((config.bind_host, config.bind_port), LoggingFTPHandler)
    server.max_cons_per_ip = 0  # un scanner ouvre beaucoup de connexions : on n'en perd aucune.
    return server


def _install_signal_handlers() -> None:
    """SIGTERM (docker stop) → SystemExit, intercepté proprement par serve_forever."""

    def _graceful(_signum: int, _frame: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _graceful)


def main() -> None:
    config = load_config()
    sink = EventSink(config.log_file)

    print(
        f"[ftp-honeypot] écoute sur {config.bind_host}:{config.bind_port} "
        f"(hostname simulé: {config.hostname}, racine leurre: {config.decoy_root})",
        file=sys.stderr,
    )

    server = build_server(config, sink)
    _install_signal_handlers()
    try:
        server.serve_forever()
    finally:
        server.close_all()
        sink.close()
        print("[ftp-honeypot] arrêt", file=sys.stderr)


if __name__ == "__main__":
    main()
