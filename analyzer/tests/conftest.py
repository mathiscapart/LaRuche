"""Rend le package analyzer importable depuis les tests."""

import sys
from pathlib import Path

# Racine du repo : permet `import analyzer.*`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
