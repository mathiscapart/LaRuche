"""Rend les modules du honeypot HTTP importables depuis les tests."""

import os
import sys
from pathlib import Path

# Désactive le jitter de latence pour des tests rapides et déterministes.
os.environ.setdefault("HTTP_JITTER_MIN_MS", "0")
os.environ.setdefault("HTTP_JITTER_MAX_MS", "0")

# honeypots/http/ contient les packages app/ et alerts/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
