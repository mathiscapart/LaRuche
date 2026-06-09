"""Configuration du honeypot SSH (EPIC-1).

Tout est lu depuis l'environnement (12-factor) : les valeurs vivent dans le
``docker-compose`` / ``.env``, jamais "baked" dans l'image. Aucun fichier de
configuration n'est livré dans le conteneur — un attaquant qui obtiendrait une
primitive de lecture ne trouve donc rien sur le filesystem, et le shell
émulé ne reflète jamais le vrai environnement du process.

Des défauts raisonnables permettent de lancer le honeypot sans aucune variable.

Variables reconnues
--------------------
- ``SSH_BIND_HOST``            adresse d'écoute (défaut ``0.0.0.0``)
- ``SSH_BIND_PORT``            port d'écoute (défaut ``2222``)
- ``SSH_HOSTNAME``             hostname simulé (défaut ``prod-srv-01``)
- ``SSH_ALLOWED_CREDENTIALS``  couples acceptés ``user:pass,user:pass`` (US-03)
- ``SSH_TARPIT_SECONDS``       délai sur tentative refusée (défaut ``2.5``)
- ``SSH_JITTER_MS_MIN/MAX``    jitter de base par commande (défaut ``2``/``18`` ms ;
                               les commandes réseau ajoutent une latence variable)
- ``SSH_LOG_FILE``             fichier JSONL tail par Filebeat (défaut
                               ``/var/log/honeypot/ssh.jsonl``)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Comptes acceptés par défaut : faibles mais réalistes. Le login root est
# toujours refusé (cf. is_allowed), quelle que soit cette liste.
DEFAULT_CREDENTIALS = "admin:admin123,admin:P@ssw0rd,ubuntu:ubuntu,user:123456,deploy:deploy2023"


@dataclass(frozen=True)
class Credential:
    """Un couple identifiant/mot de passe accepté (US-03)."""

    username: str
    password: str


@dataclass
class Config:
    """Configuration résolue du honeypot."""

    bind_host: str = "0.0.0.0"  # noqa: S104  # nosec B104 - un honeypot écoute volontairement partout
    bind_port: int = 2222
    hostname: str = "prod-srv-01"
    allowed_credentials: list[Credential] = field(default_factory=list)
    tarpit_seconds: float = 2.5
    jitter_ms_min: int = 2
    jitter_ms_max: int = 18
    log_file: str | None = "/var/log/honeypot/ssh.jsonl"

    def is_allowed(self, username: str, password: str) -> bool:
        """Vrai si le couple est accepté. Le compte root est toujours refusé."""
        if username == "root":
            return False
        return any(
            c.username == username and c.password == password
            for c in self.allowed_credentials
        )


def _parse_credentials(raw: str) -> list[Credential]:
    """Parse ``user:pass,user:pass`` en liste de Credential (entrées vides ignorées)."""
    creds: list[Credential] = []
    for item in raw.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        username, password = item.split(":", 1)
        creds.append(Credential(username=username, password=password))
    return creds


def load_config() -> Config:
    """Construit la configuration depuis les variables d'environnement."""
    log_file = os.getenv("SSH_LOG_FILE", "/var/log/honeypot/ssh.jsonl")
    return Config(
        bind_host=os.getenv("SSH_BIND_HOST", "0.0.0.0"),  # noqa: S104  # nosec B104
        bind_port=int(os.getenv("SSH_BIND_PORT", "2222")),
        hostname=os.getenv("SSH_HOSTNAME", "prod-srv-01"),
        allowed_credentials=_parse_credentials(
            os.getenv("SSH_ALLOWED_CREDENTIALS", DEFAULT_CREDENTIALS)
        ),
        tarpit_seconds=float(os.getenv("SSH_TARPIT_SECONDS", "2.5")),
        jitter_ms_min=int(os.getenv("SSH_JITTER_MS_MIN", "2")),
        jitter_ms_max=int(os.getenv("SSH_JITTER_MS_MAX", "18")),
        log_file=log_file or None,
    )
