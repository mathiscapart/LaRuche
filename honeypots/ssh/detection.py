"""Analyse comportementale des commandes (US-04, US-05, US-06, US-07).

Ce module ne produit pas de sortie shell : il qualifie les commandes et la
session pour alimenter le champ ``classification`` des événements, visible
ensuite dans OpenObserve (US-19).

- US-04 : escalade de privilèges (``sudo su``, ``su root``...) → severity HIGH
- US-05 : commandes malware (``wget``, ``curl``, reverse shell...) → CRITICAL
- US-06 : distinction bot / human via le timing inter-commandes
- US-07 : fingerprint comportemental = hash de la séquence de commandes
"""

from __future__ import annotations

import hashlib
import re
import statistics
from dataclasses import dataclass, field

# --- US-05 : signatures de commandes malveillantes --------------------------
# (regex, label) — utilisées pour tagger l'intention d'infection.
_MALWARE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bwget\b"), "download_wget"),
    (re.compile(r"\bcurl\b"), "download_curl"),
    (re.compile(r"\bchmod\s+\+?x\b|\bchmod\s+[0-7]*7[0-7]*\b"), "make_executable"),
    (re.compile(r"bash\s+-i\b"), "interactive_bash"),
    (re.compile(r"/dev/tcp/"), "bash_reverse_shell"),
    (re.compile(r"\bnc\b|\bncat\b|\bnetcat\b"), "netcat"),
    (re.compile(r"\bpython[23]?\b.*socket"), "python_reverse_shell"),
    (re.compile(r"\b(perl|ruby|php)\b.*-e\b"), "scripting_oneliner"),
    (re.compile(r"\b(tftp|ftpget)\b"), "alt_download"),
    (re.compile(r";\s*\./|\|\s*sh\b|\|\s*bash\b"), "pipe_to_shell"),
]

# --- US-04 : signatures d'escalade de privilèges ----------------------------
_ESCALATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*sudo\s+su\b"),
    re.compile(r"^\s*sudo\s+-i\b"),
    re.compile(r"^\s*sudo\s+-s\b"),
    re.compile(r"^\s*su\s+(-\s+)?root\b"),
    re.compile(r"^\s*su\s*$"),
    re.compile(r"^\s*su\s+-\s*$"),
]


def detect_malware(line: str) -> list[str]:
    """Renvoie les labels malware déclenchés par la commande (vide si aucun)."""
    return [label for pattern, label in _MALWARE_PATTERNS if pattern.search(line)]


def is_escalation(line: str) -> bool:
    """Vrai si la commande est une tentative d'escalade vers root (US-04)."""
    return any(pattern.search(line) for pattern in _ESCALATION_PATTERNS)


def classify_command(line: str) -> dict | None:
    """Construit le bloc ``classification`` d'un événement de commande.

    Renvoie ``None`` pour une commande banale (enrichie en aval si besoin).
    Priorité au malware (CRITICAL) sur l'escalade (HIGH).
    """
    malware = detect_malware(line)
    if malware:
        return {
            "category": "EXPLOIT_ATTEMPT",
            "severity": "critical",
            "confidence": 0.9,
            "tags": ["malware_command", *malware],
        }
    if is_escalation(line):
        return {
            "category": "EXPLOIT_ATTEMPT",
            "severity": "high",
            "confidence": 0.8,
            "tags": ["privilege_escalation"],
        }
    return None


@dataclass
class SessionProfiler:
    """Accumule la séquence de commandes et le timing pour profiler la session.

    Alimente US-06 (bot vs human) et US-07 (fingerprint comportemental).
    """

    commands: list[str] = field(default_factory=list)
    intervals: list[float] = field(default_factory=list)
    _last_ts: float | None = None
    interactive: bool = True  # False pour un `ssh user@host 'cmd'` (exec direct)

    def record(self, line: str, ts: float) -> None:
        """Enregistre une commande et l'intervalle depuis la précédente."""
        if self._last_ts is not None:
            self.intervals.append(ts - self._last_ts)
        self._last_ts = ts
        self.commands.append(line)

    def fingerprint(self) -> str:
        """US-07 : hash SHA-256 de la séquence de commandes de la session."""
        joined = "\n".join(self.commands)
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    def profile(self) -> str:
        """US-06 : 'bot' ou 'human' selon le timing et le mode d'exécution.

        Heuristique : exécution non interactive, ou commandes très rapprochées
        et régulières (faible variance), trahissent un automate.
        """
        if not self.interactive:
            return "bot"
        if len(self.intervals) < 2:
            # Trop court pour juger : un humain tape rarement < 2 commandes
            # en restant ; par prudence on ne sur-qualifie pas.
            return "human"
        mean = statistics.mean(self.intervals)
        stdev = statistics.pstdev(self.intervals)
        # Bot : cadence soutenue (< 0.5s en moyenne) et très régulière.
        if mean < 0.5 and stdev < 0.2:
            return "bot"
        # Bot probable : tout est quasi instantané.
        if mean < 0.15:
            return "bot"
        return "human"

    def session_classification(self) -> dict:
        """Bloc ``classification`` pour l'événement de fin de session."""
        profile = self.profile()
        tags = [f"fingerprint:{self.fingerprint()[:16]}"]
        if not self.interactive:
            tags.append("non_interactive")
        return {
            "profile": profile,
            "confidence": 0.7,
            "tags": tags,
        }
