"""Rend les modules du honeypot HTTP importables depuis les tests."""

import sys
from pathlib import Path

# honeypots/http/ contient les packages app/ et alerts/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
