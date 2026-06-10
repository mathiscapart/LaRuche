"""Lecture des événements HoneypotEvent (JSON Lines) produits par les honeypots.

Source unique de vérité pour tout l'analyzer : on lit les mêmes fichiers que
Fluent Bit (docs/event.schema.json), une ligne JSON par événement.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path


def iter_events(paths: Iterable[Path | str]) -> Iterator[dict]:
    """Itère les événements de plusieurs fichiers JSONL (lignes invalides ignorées)."""
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    yield json.loads(stripped)
                except json.JSONDecodeError:
                    continue


def load_log_dir(log_dir: Path | str) -> list[dict]:
    """Charge tous les événements des *.jsonl d'un répertoire."""
    return list(iter_events(sorted(Path(log_dir).glob("*.jsonl"))))


def group_by_session(events: Iterable[dict]) -> dict[str, list[dict]]:
    """Regroupe les événements par session (session_id, sinon src_ip)."""
    sessions: dict[str, list[dict]] = {}
    for event in events:
        key = event.get("session_id") or event.get("src_ip") or "unknown"
        sessions.setdefault(key, []).append(event)
    return sessions
