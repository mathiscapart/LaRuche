"""Client Redis pour pousser les alertes critiques (US-11).

L'envoi est best-effort : si Redis est indisponible (dev local), l'alerte est
seulement journalisée sur stderr, sans bloquer la réponse du honeypot.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from app.config import ALERT_CHANNEL, REDIS_URL

try:
    import redis
except ImportError:  # redis optionnel en dev
    redis = None

_client = None


def _get_client():
    global _client
    if redis is None:
        return None
    if _client is None:
        _client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
    return _client


def _log_stderr(event: dict[str, Any]) -> None:
    print(f"[ALERT] {json.dumps(event, ensure_ascii=False)}", file=sys.stderr, flush=True)


def push_alert(event: dict[str, Any]) -> bool:
    """Publie l'alerte sur le canal Redis + l'empile. Retourne False si indisponible."""
    client = _get_client()
    if client is None:
        _log_stderr(event)
        return False
    try:
        message = json.dumps(event, ensure_ascii=False)
        client.publish(ALERT_CHANNEL, message)
        client.lpush(ALERT_CHANNEL, message)
        return True
    except Exception:  # Redis indisponible ne doit jamais casser le honeypot
        _log_stderr(event)
        return False
