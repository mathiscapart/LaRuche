"""Configuration du honeypot FTP (EPIC-1).

Tout est lu depuis l'environnement (12-factor) : les valeurs vivent dans le
``docker-compose`` / ``.env``, jamais "baked" dans l'image. L'arborescence
servie est entièrement factice (cf. ``filesystem.py``) : aucun fichier réel du
conteneur n'est exposé, et l'attaquant est confiné (sandbox pyftpdlib) à la
racine leurre.

Des défauts raisonnables permettent de lancer le honeypot sans aucune variable.

Variables reconnues
--------------------
- ``FTP_BIND_HOST``            adresse d'écoute (défaut ``0.0.0.0``)
- ``FTP_BIND_PORT``            port de contrôle (défaut ``2121``)
- ``FTP_HOSTNAME``             hostname simulé (défaut ``prod-srv-01``)
- ``FTP_BANNER``               bannière annoncée après 220 (défaut ``(vsFTPd 3.0.3)``)
- ``FTP_ALLOWED_CREDENTIALS``  couples acceptés ``user:pass,user:pass``
- ``FTP_SSH_CREDENTIALS``      creds du honeypot SSH, acceptés aussi (capture de
                               la réutilisation SSH->FTP, mouvement latéral)
- ``FTP_ANONYMOUS``            accepte l'anonyme (défaut ``true``)
- ``FTP_DECOY_ROOT``           racine matérialisée de l'arbre leurre
                               (défaut ``/srv/ftp``)
- ``FTP_PASV_MIN`` / ``MAX``   plage de ports passifs (défaut ``30000``/``30009``)
- ``FTP_MASQUERADE_ADDRESS``   IP publique annoncée en mode passif (défaut: aucune)
- ``FTP_LOG_FILE``             fichier JSONL tail par Filebeat (défaut
                               ``/var/log/honeypot/ftp.jsonl``)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Comptes faibles mais réalistes. FTP n'autorise qu'un mot de passe par compte
# (un seul username) ; le login root est toujours refusé (cf. is_allowed).
DEFAULT_CREDENTIALS = "admin:admin123,ftp:ftp,backup:Backup2024,deploy:deploy2023"

# Identifiants acceptés par le honeypot SSH (cf. SSH_ALLOWED_CREDENTIALS). On les
# accepte AUSSI sur le FTP : un attaquant ayant moissonné des creds SSH puis les
# rejouant ici est connecté (capture maximale) ET tagué « réutilisation SSH ».
# À garder synchronisé avec SSH_ALLOWED_CREDENTIALS (cf. FTP_SSH_CREDENTIALS).
SSH_CREDENTIALS = "admin:admin123,admin:P@ssw0rd,ubuntu:ubuntu,user:123456,deploy:deploy2023"


@dataclass(frozen=True)
class Credential:
    """Un couple identifiant/mot de passe accepté."""

    username: str
    password: str


@dataclass
class Config:
    """Configuration résolue du honeypot FTP."""

    bind_host: str = "0.0.0.0"  # noqa: S104  # nosec B104 - un honeypot écoute volontairement partout
    bind_port: int = 2121
    hostname: str = "prod-srv-01"
    banner: str = "(vsFTPd 3.0.3)"
    allowed_credentials: list[Credential] = field(default_factory=list)
    ssh_credentials: list[Credential] = field(default_factory=list)
    anonymous_enabled: bool = True
    decoy_root: str = "/srv/ftp"
    pasv_min: int = 30000
    pasv_max: int = 30009
    masquerade_address: str | None = None
    log_file: str | None = "/var/log/honeypot/ftp.jsonl"

    def accepted_credentials(self) -> list[Credential]:
        """Comptes effectivement acceptés : comptes FTP + creds SSH (réutilisation),
        dédupliqués par username (FTP n'autorise qu'un mot de passe par compte),
        root exclu. Les comptes FTP priment en cas de collision de username."""
        merged: list[Credential] = []
        seen: set[str] = set()
        for cred in (*self.allowed_credentials, *self.ssh_credentials):
            if cred.username == "root" or cred.username in seen:
                continue
            seen.add(cred.username)
            merged.append(cred)
        return merged

    def is_allowed(self, username: str, password: str) -> bool:
        """Vrai si le couple est accepté (compte FTP ou cred SSH réutilisé).
        Le compte root est toujours refusé."""
        if username == "root":
            return False
        return any(
            c.username == username and c.password == password
            for c in self.accepted_credentials()
        )

    def is_ssh_credential(self, username: str, password: str) -> bool:
        """Vrai si le couple correspond à un identifiant du honeypot SSH.

        Sert à taguer la réutilisation de creds SSH sur le FTP (mouvement
        latéral / credential stuffing inter-services)."""
        if username == "root":
            return False
        return any(
            c.username == username and c.password == password
            for c in self.ssh_credentials
        )


def _parse_credentials(raw: str) -> list[Credential]:
    """Parse ``user:pass,user:pass`` ; ignore les entrées vides et les doublons
    de username (FTP n'accepte qu'un mot de passe par compte)."""
    creds: list[Credential] = []
    seen: set[str] = set()
    for raw_item in raw.split(","):
        item = raw_item.strip()
        if not item or ":" not in item:
            continue
        username, password = item.split(":", 1)
        if username in seen:
            continue
        seen.add(username)
        creds.append(Credential(username=username, password=password))
    return creds


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def load_config() -> Config:
    """Construit la configuration depuis les variables d'environnement."""
    masquerade = os.getenv("FTP_MASQUERADE_ADDRESS", "").strip()
    log_file = os.getenv("FTP_LOG_FILE", "/var/log/honeypot/ftp.jsonl")
    return Config(
        bind_host=os.getenv("FTP_BIND_HOST", "0.0.0.0"),  # noqa: S104  # nosec B104
        bind_port=int(os.getenv("FTP_BIND_PORT", "2121")),
        hostname=os.getenv("FTP_HOSTNAME", "prod-srv-01"),
        banner=os.getenv("FTP_BANNER", "(vsFTPd 3.0.3)"),
        allowed_credentials=_parse_credentials(
            os.getenv("FTP_ALLOWED_CREDENTIALS", DEFAULT_CREDENTIALS)
        ),
        ssh_credentials=_parse_credentials(
            os.getenv("FTP_SSH_CREDENTIALS", SSH_CREDENTIALS)
        ),
        anonymous_enabled=_env_bool("FTP_ANONYMOUS", default=True),
        decoy_root=os.getenv("FTP_DECOY_ROOT", "/srv/ftp"),
        pasv_min=int(os.getenv("FTP_PASV_MIN", "30000")),
        pasv_max=int(os.getenv("FTP_PASV_MAX", "30009")),
        masquerade_address=masquerade or None,
        log_file=log_file or None,
    )
