"""Émulateur de commandes du faux shell SSH (US-02).

Toutes les réponses sont fabriquées et cohérentes avec un Debian 12 (bookworm)
nommé ``prod-srv-01``. Aucune commande ne touche le vrai système : ``env``,
``cat /proc/...``, ``cat /etc/passwd`` renvoient des sorties forgées, de sorte
que la configuration réelle du conteneur n'est jamais exposée à l'attaquant.

L'état (utilisateur courant, répertoire) vit dans ``ShellState`` : il évolue
avec ``cd`` et avec l'escalade de privilèges (US-04), ce qui rend les réponses
contextuelles (prompt, ``whoami``, ``pwd``).
"""

from __future__ import annotations

from dataclasses import dataclass

# Faux /etc/passwd : comptes système plausibles d'un serveur de prod.
_ETC_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000:admin:/home/admin:/bin/bash
deploy:x:1001:1001:deploy:/home/deploy:/bin/bash"""

_OS_RELEASE = """PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/\""""

_UNAME = "Linux prod-srv-01 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64 GNU/Linux"

_PS_AUX = """USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1 167404 11248 ?        Ss   Jan31   0:12 /sbin/init
root         412  0.0  0.0  22372  6120 ?        Ss   Jan31   0:01 /lib/systemd/systemd-journald
root         598  0.0  0.0  15428  6884 ?        Ss   Jan31   0:00 /usr/sbin/sshd -D
root         640  0.0  0.0   8356  3220 ?        Ss   Jan31   0:03 /usr/sbin/cron -f
postgres     812  0.0  0.4 218460 33980 ?        Ss   Jan31   1:44 /usr/lib/postgresql/15/bin/postgres
www-data     998  0.0  0.1  55180  9760 ?        S    Jan31   0:21 nginx: worker process
root        1002  0.0  0.0  55064  3120 ?        Ss   Jan31   0:00 nginx: master process
admin       2231  0.0  0.0  17668  5560 pts/0    Ss   09:02   0:00 -bash
admin       2240  0.0  0.0  21952  3540 pts/0    R+   09:14   0:00 ps aux"""

_SS_OUTPUT = """Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=598))
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*     users:(("nginx",pid=1002))
tcp   LISTEN 0      511          0.0.0.0:443        0.0.0.0:*     users:(("nginx",pid=1002))
tcp   LISTEN 0      244        127.0.0.1:5432       0.0.0.0:*     users:(("postgres",pid=812))"""

_NETSTAT = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
tcp        0      0 10.0.2.15:22            10.0.2.2:51344          ESTABLISHED"""

_DF = """Filesystem      Size  Used Avail Use% Mounted on
udev            1.9G     0  1.9G   0% /dev
tmpfs           395M  1.1M  394M   1% /run
/dev/sda1        49G   12G   35G  26% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
/dev/sda15      124M  6.1M  118M   5% /boot/efi"""

_CPUINFO = """processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Silver 4210 CPU @ 2.20GHz
stepping\t: 7
microcode\t: 0x5003604
cpu MHz\t\t: 2200.000
cache size\t: 14080 KB
physical id\t: 0
siblings\t: 4
core id\t\t: 0
cpu cores\t: 4
fpu\t\t: yes
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge sse sse2 ht"""

_HISTORY = [
    "cd /var/www/app",
    "git pull origin main",
    "sudo systemctl restart nginx",
    "docker ps",
    "docker compose logs -f web",
    "tail -f /var/log/nginx/error.log",
    "vim config.yml",
    "apt update",
    "apt upgrade -y",
    "df -h",
    "free -m",
    "psql -U postgres -d appdb",
    "systemctl status postgresql",
    "htop",
    "netstat -tulnp",
    "scp backup.tar.gz deploy@10.0.2.50:/backups/",
    "crontab -l",
    "cat /etc/nginx/sites-enabled/app.conf",
    "journalctl -u nginx --since '1 hour ago'",
    "exit",
]

_LAST = """admin    pts/0        10.0.2.2         Mon Jun  9 09:02   still logged in
admin    pts/0        10.0.2.2         Fri Jun  6 18:41 - 19:55  (01:14)
deploy   pts/1        10.0.2.50        Fri Jun  6 14:22 - 15:03  (00:41)
reboot   system boot  5.10.0-28-amd64  Wed Jan 31 11:18   still running

wtmp begins Wed Jan 31 11:18:02 2024"""

_LS_HOME = "app  backup.tar.gz  notes.txt"
_LS_HOME_LONG = """total 28
drwxr-xr-x 3 {user} {user} 4096 Jun  9 09:02 .
drwxr-xr-x 4 root  root  4096 Jun  6 18:40 ..
-rw------- 1 {user} {user}  220 Jun  6 18:40 .bash_history
-rw-r--r-- 1 {user} {user} 3526 Jun  6 18:40 .bashrc
drwxr-xr-x 6 {user} {user} 4096 Jun  9 09:01 app
-rw-r--r-- 1 {user} {user} 8192 Jun  6 18:41 backup.tar.gz
-rw-r--r-- 1 {user} {user}  142 Jun  6 18:41 notes.txt"""


@dataclass
class ShellState:
    """État courant de la session shell (contexte des réponses)."""

    hostname: str = "prod-srv-01"
    user: str = "admin"
    cwd: str = "/home/admin"
    is_root: bool = False

    def prompt(self) -> str:
        """Prompt réaliste : ``$`` pour un user, ``#`` pour root."""
        symbol = "#" if self.is_root else "$"
        # Affiche ~ quand on est dans le home de l'utilisateur courant.
        home = "/root" if self.is_root else f"/home/{self.user}"
        location = "~" if self.cwd == home else self.cwd
        return f"{self.user}@{self.hostname}:{location}{symbol} "

    def escalate_to_root(self) -> None:
        """Passe la session en contexte root (appelé après une escalade réussie)."""
        self.user = "root"
        self.is_root = True
        self.cwd = "/root"


def _id_line(state: ShellState) -> str:
    if state.is_root:
        return "uid=0(root) gid=0(root) groups=0(root)"
    return f"uid=1000({state.user}) gid=1000({state.user}) groups=1000({state.user}),27(sudo)"


def run_command(state: ShellState, line: str) -> str:
    """Exécute (simule) une commande et renvoie sa sortie texte.

    L'appelant gère la journalisation, le jitter et la détection ; cette
    fonction ne produit que la sortie visible par l'attaquant. Une commande
    inconnue renvoie le message ``command not found`` de bash.
    """
    line = line.strip()
    if not line:
        return ""

    parts = line.split()
    cmd = parts[0]
    args = parts[1:]
    home = "/root" if state.is_root else f"/home/{state.user}"

    # --- commandes à réponse fixe -------------------------------------------
    if cmd == "pwd":
        return state.cwd
    if cmd == "whoami":
        return state.user
    if cmd == "id":
        return _id_line(state)
    if cmd == "hostname":
        return state.hostname
    if cmd == "uname":
        return _UNAME if "-a" in args else "Linux"
    if cmd == "uptime":
        return " 09:14:02 up 129 days,  3:56,  1 user,  load average: 0.08, 0.03, 0.01"
    if cmd == "history":
        return "\n".join(f"{i:5d}  {c}" for i, c in enumerate(_HISTORY, start=1))
    if cmd in ("ps",):
        return _PS_AUX
    if cmd == "ss":
        return _SS_OUTPUT
    if cmd == "netstat":
        return _NETSTAT
    if cmd == "df":
        return _DF
    if cmd in ("who", "w"):
        return "admin    pts/0        2024-06-09 09:02 (10.0.2.2)"
    if cmd == "last":
        return _LAST
    if cmd in ("free",):
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:            3936         812        2103          12        1020        2884\n"
            "Swap:            974           0         974"
        )

    # --- env / variables : sorties forgées (jamais le vrai process env) -----
    if cmd in ("env", "printenv", "set"):
        return (
            f"SHELL=/bin/bash\nUSER={state.user}\nHOME={home}\n"
            f"PWD={state.cwd}\nLANG=en_US.UTF-8\nLOGNAME={state.user}\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "TERM=xterm-256color\nHOSTNAME=prod-srv-01"
        )

    # --- cat de fichiers connus ---------------------------------------------
    if cmd == "cat":
        return _cat(args)

    # --- ls ------------------------------------------------------------------
    if cmd in ("ls", "dir"):
        if "-l" in args or "-la" in args or "-al" in args:
            return _LS_HOME_LONG.format(user=state.user)
        return _LS_HOME

    # --- cd : met à jour l'état, pas de sortie ------------------------------
    if cmd == "cd":
        target = args[0] if args else home
        if target == "~" or target == "":
            state.cwd = home
        elif target == "..":
            state.cwd = state.cwd.rsplit("/", 1)[0] or "/"
        elif target.startswith("/"):
            state.cwd = target
        else:
            state.cwd = f"{state.cwd.rstrip('/')}/{target}"
        return ""

    if cmd == "echo":
        return " ".join(args)

    if cmd in ("exit", "logout"):
        return ""

    if cmd == "clear":
        return ""

    # --- commande inconnue ---------------------------------------------------
    return f"bash: {cmd}: command not found"


def _cat(args: list[str]) -> str:
    """Réponses forgées pour ``cat`` sur les fichiers couramment sondés."""
    if not args:
        return ""
    target = args[0]
    table = {
        "/etc/passwd": _ETC_PASSWD,
        "/etc/os-release": _OS_RELEASE,
        "/proc/cpuinfo": _CPUINFO,
        "/proc/version": _UNAME,
    }
    if target in table:
        return table[target]
    if target == "/etc/shadow":
        # Lecture refusée pour rester crédible.
        return "cat: /etc/shadow: Permission denied"
    return f"cat: {target}: No such file or directory"
