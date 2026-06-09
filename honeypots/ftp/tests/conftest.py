"""Rend les modules du honeypot FTP importables depuis les tests."""

import sys
from pathlib import Path

# honeypots/ftp/ contient les modules (config, detection, events, filesystem).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
