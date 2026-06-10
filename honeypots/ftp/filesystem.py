"""Arborescence factice servie par le honeypot FTP (US — reconnaissance).

Le honeypot ne sert JAMAIS le vrai système de fichiers : au démarrage, on
matérialise sous ``decoy_root`` une arborescence entièrement forgée, en lecture
seule, et pyftpdlib confine l'attaquant à cette racine (pas d'échappement via
``..``). LIST / CWD / PWD opèrent donc nativement sur du contenu leurre.

Les dossiers ``backup`` / ``conf`` / ``exports`` (+ fichiers d'appât) servent à
capturer la reconnaissance : un attaquant qui liste, navigue puis tente de
récupérer ``conf/database.yml`` ou ``conf/.env`` est immédiatement qualifié.

NB : les "secrets" ci-dessous sont des leurres synthétiques (hôtes ``.lan``,
valeurs ``ChangeMe`` / ``EXAMPLE``) — crédibles pour un humain mais sans format
déclenchant un scanner de secrets.
"""

from __future__ import annotations

import os
from pathlib import Path

# mtime figés (passé) pour des listings crédibles et déterministes.
_MTIME_OLD = 1735730000  # ~ 2025-01-01
_MTIME_RECENT = 1748600000  # ~ 2025-05-30

_README = (
    "Serveur de fichiers interne — prod-srv-01\n"
    "Accès réservé à l'équipe ops. Les sauvegardes sont dans backup/.\n"
    "Toute connexion est journalisée.\n"
)

_BACKUP_NOTES = (
    "Rotation des sauvegardes (hebdomadaire, dimanche 02:00).\n"
    "- db_prod_*.sql.gz   : dump PostgreSQL appdb_prod\n"
    "- www_*.tar.gz       : /var/www/app\n"
    "Procédure de restauration : voir conf/runbook interne.\n"
)

_NGINX_CONF = (
    "server {\n"
    "    listen 443 ssl;\n"
    "    server_name app.example.lan;\n"
    "    ssl_certificate     /etc/nginx/ssl/app.crt;\n"
    "    ssl_certificate_key /etc/nginx/ssl/app.key;\n"
    "    root /var/www/app/public;\n"
    "    location / {\n"
    "        proxy_pass http://127.0.0.1:8000;\n"
    "        proxy_set_header Host $host;\n"
    "    }\n"
    "}\n"
)

_DATABASE_YML = (
    "production:\n"
    "  adapter: postgresql\n"
    "  host: db-prod-01.internal.lan\n"
    "  port: 5432\n"
    "  database: appdb_prod\n"
    "  username: app_prod\n"
    "  password: Pr0d_DB_ChangeMe_2024\n"
    "  pool: 25\n"
)

_APP_ENV = (
    "APP_ENV=production\n"
    "APP_DEBUG=false\n"
    "APP_URL=https://app.example.lan\n"
    "DB_HOST=db-prod-01.internal.lan\n"
    "DB_DATABASE=appdb_prod\n"
    "DB_USERNAME=app_prod\n"
    "DB_PASSWORD=Pr0d_DB_ChangeMe_2024\n"
    "REDIS_HOST=cache-01.internal.lan\n"
    "MAIL_HOST=smtp.internal.lan\n"
)

_CLIENTS_CSV = (
    "id,nom,email,ville,segment\n"
    "1001,Dupont SARL,contact@dupont.example,Lille,PME\n"
    "1002,Martin & Cie,achats@martin.example,Lyon,ETI\n"
    "1003,Bernard SA,facturation@bernard.example,Paris,GE\n"
    "1004,Petit Logistique,ops@petit.example,Nantes,PME\n"
)

_SALARY_CSV = (
    "matricule,nom,poste,salaire_brut_annuel\n"
    "E0042,Leroy J.,Lead Dev,72000\n"
    "E0051,Moreau S.,DevOps,61000\n"
    "E0067,Garnier A.,SRE,64000\n"
)

# Appât d'identifiants "oubliés" : crédible pour un humain, mais valeurs
# synthétiques (``ChangeMe``) ne déclenchant pas un scanner de secrets. Son
# téléchargement est un signal d'exfiltration majeur (canary).
_CREDENTIALS_OLD = (
    "# Anciens accès de service — rotation 2023 (NE PAS DIFFUSER)\n"
    "# Laissé ici par erreur, à migrer vers le coffre interne.\n"
    "# service     compte         mot_de_passe\n"
    "ftp           deploy         Depl0y_OLD_ChangeMe\n"
    "postgres      app_prod       Pr0d_DB_ChangeMe_2024\n"
    "smtp          noreply        Mail_ChangeMe_2023\n"
    "vpn-backup    svc-backup     Vpn_ChangeMe_2023\n"
)

# Arbre leurre : un dict = un dossier ; une valeur texte = un fichier.
DECOY_TREE: dict[str, object] = {
    "README.txt": _README,
    "backup": {
        # Fichiers canary (appâts téléchargeables, cf. CANARY_FILES).
        "backup_2024-06-01.tar.gz": "gzip backup placeholder — /var/www/app + appdb_prod\n",
        "db_dump.sql.gz": "-- dump PostgreSQL appdb_prod (tronqué)\n",
        "db_prod_2025-05-30.sql.gz": "-- dump PostgreSQL (tronqué)\n",
        "www_2025-05-30.tar.gz": "binary backup placeholder\n",
        "NOTES.txt": _BACKUP_NOTES,
    },
    "conf": {
        "nginx.conf": _NGINX_CONF,
        "database.yml": _DATABASE_YML,
        ".env": _APP_ENV,
        # Fichier canary (appât d'identifiants, cf. CANARY_FILES).
        "credentials_old.txt": _CREDENTIALS_OLD,
    },
    "exports": {
        "clients_export_2026Q1.csv": _CLIENTS_CSV,
        "rh_salaires_2025.csv": _SALARY_CSV,
    },
}


def _write_node(base: Path, node: dict[str, object]) -> None:
    base.mkdir(parents=True, exist_ok=True)
    os.utime(base, (_MTIME_RECENT, _MTIME_RECENT))
    for name, content in node.items():
        target = base / name
        if isinstance(content, dict):
            _write_node(target, content)
        else:
            text = content if isinstance(content, str) else str(content)
            target.write_text(text, encoding="utf-8")
            mtime = _MTIME_OLD if name.endswith((".gz", ".conf")) else _MTIME_RECENT
            os.utime(target, (mtime, mtime))


def materialize(root: str) -> str:
    """(Re)matérialise l'arborescence leurre sous ``root``. Idempotent.

    Renvoie le chemin racine. Sûr à rappeler : ``exist_ok`` partout, contenu
    réécrit à l'identique.
    """
    root_path = Path(root)
    _write_node(root_path, DECOY_TREE)
    return str(root_path)


def decoy_dirs() -> list[str]:
    """Chemins FTP des dossiers leurres de premier niveau (``/backup`` ...)."""
    return [f"/{name}" for name, node in DECOY_TREE.items() if isinstance(node, dict)]


# Fichiers "canary" : appâts sensibles dont le TÉLÉCHARGEMENT (RETR) est un
# signal fort d'exfiltration de données. Tout téléchargement de l'un d'eux est
# qualifié ``CANARY_TRIGGERED`` / ``critical`` (cf. detection.classify_download).
# Chemins exprimés en vue FTP (côté attaquant), pas en chemins disque.
CANARY_FILES: frozenset[str] = frozenset(
    {
        "/backup/backup_2024-06-01.tar.gz",
        "/backup/db_dump.sql.gz",
        "/conf/credentials_old.txt",
        "/conf/.env",
        "/conf/database.yml",
    }
)


def is_canary(ftp_path: str) -> bool:
    """Vrai si le chemin FTP désigne un fichier canary (appât sensible)."""
    return ftp_path in CANARY_FILES
