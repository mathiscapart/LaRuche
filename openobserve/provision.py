#!/usr/bin/env python3
"""Provisionne les dashboards OpenObserve (US-19).

Importe tous les `dashboards/*.json` (format importable OpenObserve, façon
provisioning Grafana). Idempotent : un dashboard de même titre est supprimé
puis recréé. Attend qu'OpenObserve réponde avant d'importer.

Exécuté de deux façons :
- au démarrage de la stack par le service `dashboard-provisioner` (compose) ;
- à la main : `python3 openobserve/provision.py`.

Stdlib uniquement (aucune dépendance) — tourne tel quel dans `python:slim`.
Config via l'environnement :
  OPENOBSERVE_URL (def http://localhost:5080), OPENOBSERVE_ORG (def default),
  OPENOBSERVE_USER, OPENOBSERVE_PASSWORD, DASHBOARDS_DIR, WAIT_TIMEOUT (s).
"""

from __future__ import annotations

import base64
import glob
import json
import os
import time
import urllib.error
import urllib.request

URL = os.environ.get("OPENOBSERVE_URL", "http://localhost:5080").rstrip("/")
ORG = os.environ.get("OPENOBSERVE_ORG", "default")
USER = os.environ.get("OPENOBSERVE_USER", "admin@laruche.local")
PASSWORD = os.environ.get("OPENOBSERVE_PASSWORD", "Honeypot2026!")
DASHBOARDS_DIR = os.environ.get(
    "DASHBOARDS_DIR", os.path.join(os.path.dirname(__file__), "dashboards")
)
WAIT_TIMEOUT = int(os.environ.get("WAIT_TIMEOUT", "120"))

_AUTH = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


def _req(method: str, path: str, body: bytes | None = None):
    req = urllib.request.Request(f"{URL}{path}", data=body, method=method)
    req.add_header("Authorization", _AUTH)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        raw = resp.read().decode()
        return resp.status, (json.loads(raw) if raw else {})


def wait_ready() -> None:
    deadline = time.time() + WAIT_TIMEOUT
    while time.time() < deadline:
        try:
            _req("GET", f"/api/{ORG}/dashboards?folder=default")
            print(f"[provision] OpenObserve prêt sur {URL}")
            return
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            print(f"[provision] attente OpenObserve… ({exc})")
            time.sleep(3)
    raise SystemExit(f"[provision] OpenObserve injoignable après {WAIT_TIMEOUT}s")


def existing_by_title(title: str) -> list[str]:
    _, data = _req("GET", f"/api/{ORG}/dashboards?folder=default")
    out = []
    for d in data.get("dashboards", []):
        inner = d.get("v3") or d.get("v2") or d.get("v1") or {}
        if inner.get("title") == title:
            out.append(inner.get("dashboardId"))
    return [i for i in out if i]


def main() -> None:
    wait_ready()
    files = sorted(glob.glob(os.path.join(DASHBOARDS_DIR, "*.json")))
    if not files:
        raise SystemExit(f"[provision] aucun dashboard dans {DASHBOARDS_DIR}")
    for path in files:
        with open(path, encoding="utf-8") as fh:
            dash = json.load(fh)
        title = dash["title"]
        for did in existing_by_title(title):
            _req("DELETE", f"/api/{ORG}/dashboards/{did}?folder=default")
            print(f"[provision] supprimé ancien '{title}' ({did})")
        status, _ = _req(
            "POST", f"/api/{ORG}/dashboards?folder=default",
            json.dumps(dash).encode(),
        )
        print(f"[provision] [{status}] importé '{title}'  <-  {os.path.basename(path)}")
    print("[provision] terminé.")


if __name__ == "__main__":
    main()
