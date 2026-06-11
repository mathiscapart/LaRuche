"""Télécharge les bases MaxMind GeoLite2 (City + ASN) dans un dossier cible.

Utilisé au build (stage jetable du Dockerfile analyzer) pour embarquer les bases
dans l'image — stdlib uniquement, donc pas besoin de curl/apt dans l'image de
build (conforme hadolint : ni apt non pinné, ni pipe). Sans MAXMIND_LICENSE_KEY,
ne télécharge rien : le dossier reste vide et GeoIP renvoie des champs vides.

Usage : python fetch_geoip.py [dest_dir]   (clé lue depuis MAXMIND_LICENSE_KEY)
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import urllib.request

EDITIONS = ("GeoLite2-City", "GeoLite2-ASN")
_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id={ed}&license_key={key}&suffix=tar.gz"
)


def fetch(dest: str, key: str) -> None:
    os.makedirs(dest, exist_ok=True)
    if not key:
        print("MAXMIND_LICENSE_KEY absent : pas de téléchargement (GeoIP restera vide).")
        return
    for ed in EDITIONS:
        with urllib.request.urlopen(_URL.format(ed=ed, key=key), timeout=60) as resp:
            payload = resp.read()
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            member = next(m for m in tar.getmembers() if m.name.endswith(f"{ed}.mmdb"))
            member.name = f"{ed}.mmdb"  # aplatit (retire le dossier daté)
            tar.extract(member, dest, filter="data")
        print(f"{ed}.mmdb -> {dest}")


if __name__ == "__main__":
    dest_dir = sys.argv[1] if len(sys.argv) > 1 else "/geoip"
    fetch(dest_dir, os.environ.get("MAXMIND_LICENSE_KEY", ""))
