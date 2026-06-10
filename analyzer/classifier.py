"""Classifieur comportemental de sessions (US-30).

Distingue 4 profils à partir de features extraites d'une session (events d'une
même IP/session) : volume et part des tentatives d'auth, largeur de
reconnaissance (chemins distincts), cadence (events/min) et régularité du timing
(coefficient de variation des écarts inter-événements).

Fournit aussi le calcul d'une matrice de confusion (precision / recall / F1 par
profil + accuracy globale) pour valider la précision > 85% sur des sessions
réelles (Hydra, Nikto) une fois les logs collectés (J2).
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable
from datetime import datetime

PROFILES = ("bot", "bruteforcer", "human", "scanner")

# --- Seuils chiffrés (US-30) ------------------------------------------------
BRUTEFORCE_MIN_AUTH = 8          # nb minimum de tentatives d'auth dans la session
BRUTEFORCE_AUTH_RATIO = 0.6      # part des events qui sont des tentatives d'auth
SCANNER_MIN_DISTINCT_PATHS = 20  # largeur de reconnaissance (Nikto & co)
SCANNER_UA_MIN_PATHS = 10        # breadth minimale si UA de scanner détecté
BOT_MIN_RATE_PER_MIN = 30        # cadence soutenue (events/min)
BOT_MAX_TIMING_CV = 0.35         # timing très régulier => automatisé

_AUTH_TYPES = {"credential_attempt", "auth_attempt", "auth_success"}


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def session_features(events: Iterable[dict]) -> dict:
    """Extrait les features d'une session."""
    events = list(events)
    n = len(events)
    times = sorted(t for t in (_parse_ts(e.get("timestamp", "")) for e in events) if t)
    duration = (times[-1] - times[0]).total_seconds() if len(times) >= 2 else 0.0
    rate = n / (duration / 60) if duration > 0 else float(n)
    gaps = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
    mean_gap = statistics.fmean(gaps) if gaps else 0.0
    timing_cv = statistics.pstdev(gaps) / mean_gap if gaps and mean_gap > 0 else 0.0
    n_auth = sum(1 for e in events if e.get("event_type") in _AUTH_TYPES)
    paths = {
        (e.get("payload") or {}).get("path")
        for e in events
        if (e.get("payload") or {}).get("path")
    }
    is_scanner_ua = any((e.get("payload") or {}).get("is_scanner") for e in events)
    return {
        "n_events": n,
        "duration_s": duration,
        "rate_per_min": rate,
        "n_auth": n_auth,
        "auth_ratio": n_auth / n if n else 0.0,
        "n_distinct_paths": len(paths),
        "timing_cv": timing_cv,
        "is_scanner_ua": is_scanner_ua,
    }


class BehaviorClassifier:
    """Classifieur à seuils — explicable et chiffré (cf. constantes ci-dessus)."""

    def classify_session(self, events: Iterable[dict]) -> str:
        f = session_features(events)
        # 1) Bruteforcer : l'authentification domine, en volume (ex. Hydra).
        if f["n_auth"] >= BRUTEFORCE_MIN_AUTH and f["auth_ratio"] >= BRUTEFORCE_AUTH_RATIO:
            return "bruteforcer"
        # 2) Scanner : large reconnaissance (ex. Nikto) ou UA de scanner + breadth.
        if f["n_distinct_paths"] >= SCANNER_MIN_DISTINCT_PATHS or (
            f["is_scanner_ua"] and f["n_distinct_paths"] >= SCANNER_UA_MIN_PATHS
        ):
            return "scanner"
        # 3) Bot : cadence élevée et timing régulier (automatisé).
        if f["rate_per_min"] >= BOT_MIN_RATE_PER_MIN and f["timing_cv"] <= BOT_MAX_TIMING_CV:
            return "bot"
        # 4) Humain interactif : peu d'events, cadence lente / irrégulière.
        return "human"


def confusion_matrix(labeled: Iterable[tuple[str, str]]) -> dict[str, dict[str, int]]:
    """Construit la matrice de confusion depuis des couples (vrai, prédit)."""
    matrix = {true: dict.fromkeys(PROFILES, 0) for true in PROFILES}
    for true, predicted in labeled:
        matrix[true][predicted] += 1
    return matrix


def matrix_metrics(matrix: dict[str, dict[str, int]]) -> dict:
    """precision / recall / F1 par profil + accuracy globale."""
    total = sum(matrix[t][p] for t in matrix for p in matrix[t])
    correct = sum(matrix[label][label] for label in matrix)
    per_profile = {}
    for label in matrix:
        tp = matrix[label][label]
        fp = sum(matrix[t][label] for t in matrix) - tp
        fn = sum(matrix[label].values()) - tp
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        per_profile[label] = {"precision": precision, "recall": recall, "f1": f1}
    return {"accuracy": correct / total if total else 0.0, "per_profile": per_profile}
