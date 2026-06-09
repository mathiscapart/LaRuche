"""Construction et écriture des événements honeypot FTP (US-01).

Identique au sink du honeypot SSH (mêmes garanties, même schéma) mais avec
``service = "ftp"``. Chaque événement est conforme à ``docs/event.schema.json``
(HoneypotEvent v1). Sortie : une ligne JSON par événement (JSON Lines), sur
``stdout`` (logs Docker) et, optionnellement, dans un fichier tail par Filebeat
puis expédié au SIEM (Wazuh).
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

SCHEMA_VERSION = "1.0.0"
SERVICE = "ftp"


def _now_iso() -> str:
    """Timestamp ISO 8601 UTC avec millisecondes, ex: 2024-06-03T08:45:12.123Z."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def normalize_ipv4(addr: str) -> str:
    """Ramène une adresse à sa forme IPv4 attendue par le schéma.

    Une socket peut remonter une IPv4 mappée IPv6 (``::ffff:127.0.0.1``) ou
    ``::1`` en boucle locale. On déplie le mapping et on rabat le loopback IPv6
    sur ``127.0.0.1`` pour respecter ``format: ipv4``.
    """
    if addr.startswith("::ffff:") and "." in addr:
        return addr.rsplit(":", 1)[-1]
    if addr in ("::1", "::"):
        return "127.0.0.1"
    return addr


def build_event(
    *,
    event_type: str,
    src_ip: str,
    src_port: int,
    session_id: str,
    payload: dict[str, Any],
    classification: dict[str, Any] | None = None,
    honeypot_host: str = "prod-srv-01",
) -> dict[str, Any]:
    """Assemble un événement conforme au schéma HoneypotEvent."""
    event: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "service": SERVICE,
        "event_type": event_type,
        "src_ip": normalize_ipv4(src_ip),
        "src_port": src_port,
        "session_id": session_id,
        "payload": payload,
        "meta": {
            "honeypot_host": honeypot_host,
            "schema_version": SCHEMA_VERSION,
        },
    }
    if classification:
        event["classification"] = classification
    return event


class EventSink:
    """Écrit les événements en JSON Lines sur stdout et (optionnellement) un fichier.

    Le fichier est ouvert en append et flush à chaque ligne pour que Filebeat
    voie les événements en quasi temps réel. Une panne d'écriture fichier ne
    doit jamais interrompre le honeypot : on retombe sur stdout seul.
    """

    def __init__(self, log_file: str | None = None, *, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self._file: TextIO | None = None
        if log_file:
            try:
                path = Path(log_file)
                path.parent.mkdir(parents=True, exist_ok=True)
                self._file = path.open("a", encoding="utf-8")
            except OSError as exc:  # pragma: no cover - dépend du FS
                print(f"[events] fichier de log indisponible ({exc}), stdout seul", file=sys.stderr)

    def emit(self, event: dict[str, Any]) -> None:
        """Sérialise et écrit un événement sur toutes les sorties disponibles."""
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        print(line, file=self._stream, flush=True)
        if self._file is not None:
            try:
                self._file.write(line + "\n")
                self._file.flush()
            except OSError as exc:  # pragma: no cover - dépend du FS
                print(f"[events] écriture fichier échouée: {exc}", file=sys.stderr)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
