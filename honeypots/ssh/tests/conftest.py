"""Rend les modules du honeypot importables depuis les tests."""

import sys
from pathlib import Path

# honeypots/ssh/ contient les modules (config, commands, detection, ...).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
