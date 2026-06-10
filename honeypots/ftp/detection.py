"""Qualification de la reconnaissance FTP (classification + profilage).

Ce module ne produit aucune réponse protocole : il qualifie les commandes
(reconnaissance) et la session (bot / scanner / human, fingerprint) pour
alimenter le champ ``classification`` des événements, sur lequel le SIEM
(Wazuh) déclenche ses alertes — exactement comme le honeypot SSH.

- Listing / navigation (LIST, NLST, CWD, PWD...) → ``category: RECON``
- Accès à un dossier leurre sensible (/backup, /conf, /exports) → severity bump
- Session quasi exclusivement de la reco → ``profile: scanner``
- Fingerprint comportemental = hash de la séquence de commandes (regroupement)
"""

from __future__ import annotations

import hashlib
import statistics
from dataclasses import dataclass, field

# Commandes de listing (transfèrent un listing sur le canal de données).
_LISTING_COMMANDS = {"LIST", "NLST", "MLSD", "MLST", "STAT"}
# Commandes de navigation / position.
_NAV_COMMANDS = {"CWD", "XCWD", "CDUP", "XCUP", "PWD", "XPWD"}
# Métadonnées / empreinte serveur. NB : TYPE est volontairement exclu (envoyé
# par tout client avant un transfert, il diluerait le signal de reco).
_PROBE_COMMANDS = {"SIZE", "MDTM", "SYST", "FEAT"}

_RECON_COMMANDS = _LISTING_COMMANDS | _NAV_COMMANDS | _PROBE_COMMANDS

# Dossiers leurres "sensibles" : y accéder renforce le signal de recon ciblée.
_SENSITIVE_DIRS = ("/backup", "/conf", "/exports")


def is_recon(cmd: str) -> bool:
    """Vrai si la commande est un signal de reconnaissance."""
    return cmd.upper() in _RECON_COMMANDS


def _touches_sensitive(arg: str, cwd: str) -> bool:
    """Vrai si la commande vise (ou se déroule dans) un dossier leurre sensible."""
    if cwd.startswith(_SENSITIVE_DIRS):
        return True
    if not arg:
        return False
    probe = arg if arg.startswith("/") else f"{cwd.rstrip('/')}/{arg}"
    return probe.startswith(_SENSITIVE_DIRS)


def classify_command(cmd: str, arg: str = "", cwd: str = "/") -> dict | None:
    """Construit le bloc ``classification`` d'un événement de commande.

    Renvoie ``None`` pour une commande banale (auth, transfert, contrôle de
    session) : seule la reconnaissance est qualifiée ici.
    """
    cmd = cmd.upper()
    if cmd not in _RECON_COMMANDS:
        return None

    tags = ["recon"]
    if cmd in _LISTING_COMMANDS:
        tags.append("directory_listing")
    elif cmd in _NAV_COMMANDS:
        tags.append("directory_navigation")
    else:
        tags.append("server_probe")

    severity = "low"
    if _touches_sensitive(arg, cwd):
        tags.append("sensitive_decoy_access")
        severity = "medium"

    return {
        "category": "RECON",
        "severity": severity,
        "confidence": 0.6,
        "tags": tags,
    }


@dataclass
class SessionProfiler:
    """Accumule la séquence de commandes et le timing pour profiler la session.

    Alimente le profil (bot / scanner / human) et le fingerprint comportemental
    de l'événement de fin de session.
    """

    commands: list[str] = field(default_factory=list)
    intervals: list[float] = field(default_factory=list)
    _last_ts: float | None = None

    def record(self, line: str, ts: float) -> None:
        """Enregistre une commande et l'intervalle depuis la précédente."""
        if self._last_ts is not None:
            self.intervals.append(ts - self._last_ts)
        self._last_ts = ts
        self.commands.append(line)

    def fingerprint(self) -> str:
        """Hash SHA-256 de la séquence de commandes de la session."""
        joined = "\n".join(self.commands)
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    def _recon_ratio(self) -> float:
        if not self.commands:
            return 0.0
        recon = sum(
            1 for c in self.commands if c.split(" ", 1)[0].upper() in _RECON_COMMANDS
        )
        return recon / len(self.commands)

    def _is_machine_paced(self) -> bool:
        """Cadence machine : commandes rapprochées et régulières."""
        if len(self.intervals) < 2:
            return False
        mean = statistics.mean(self.intervals)
        stdev = statistics.pstdev(self.intervals)
        return (mean < 0.5 and stdev < 0.2) or mean < 0.15

    def profile(self) -> str:
        """'scanner', 'bot' ou 'human' selon le contenu et le timing.

        - Session quasi exclusivement de la reconnaissance → scanner.
        - Sinon, cadence machine soutenue et régulière → bot.
        - Sinon → human.
        """
        if self._recon_ratio() >= 0.8 and len(self.commands) >= 3:
            return "scanner"
        if self._is_machine_paced():
            return "bot"
        return "human"

    def session_classification(self) -> dict:
        """Bloc ``classification`` pour l'événement de fin de session."""
        tags = [f"fingerprint:{self.fingerprint()[:16]}"]
        if self.commands and self._recon_ratio() >= 0.8:
            tags.append("recon_session")
        return {
            "profile": self.profile(),
            "confidence": 0.7,
            "tags": tags,
        }
