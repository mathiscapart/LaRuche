"""Détection de scanners (US-12) : user-agents connus et tentatives de webshell."""

from __future__ import annotations

import re

# User-agents d'outils offensifs / scanners courants (US-12 + extras).
_SCANNER_UA = re.compile(
    r"sqlmap|nikto|nuclei|gobuster|dirsearch|burpsuite|burp|masscan|nmap|wpscan|"
    r"acunetix|nessus|zgrab|ffuf|feroxbuster|python-requests|go-http-client",
    re.IGNORECASE,
)

# Tentatives de webshell : noms de shells connus OU script exécutable déposé
# dans un répertoire d'upload (on évite de flaguer les .php légitimes du CMS).
_WEBSHELL = re.compile(
    r"\b(shell|cmd|c99|r57|wso|b374k|alfa|webshell|backdoor|0day|gel4y|adminer)"
    r"\.(php\d?|phtml|asp|aspx|jsp|jspx)\b"
    r"|/(uploads?|tmp|images|media|files|wp-content/uploads)/[^?]*"
    r"\.(php\d?|phtml|asp|aspx|jsp|jspx)\b",
    re.IGNORECASE,
)


def is_scanner(user_agent: str) -> bool:
    """True si le User-Agent correspond à un scanner connu."""
    return bool(_SCANNER_UA.search(user_agent or ""))


def looks_like_webshell(path: str, filename: str = "") -> bool:
    """True si le chemin ou le fichier ressemble à un webshell."""
    return bool(_WEBSHELL.search(path or "") or _WEBSHELL.search(filename or ""))
