"""Émulateur de commandes du faux shell SSH (US-02).

Toutes les réponses sont fabriquées et cohérentes avec un Debian 12 (bookworm)
nommé ``prod-srv-01``. Aucune commande ne touche le vrai système : ``env``,
``cat /proc/...``, ``cat /etc/passwd`` renvoient des sorties forgées, de sorte
que la configuration réelle du conteneur n'est jamais exposée à l'attaquant.

L'objectif est qu'un bot ou un attaquant croie être dans un vrai environnement :
expansion des variables (``echo $HOME``), ``ls`` conscient du chemin, fichiers
``/etc/*`` présents, outils standards (ip, date, which, nproc, lscpu...),
``sudo -l`` appâtant, et simulation crédible de ``wget``/``curl``.

L'état (utilisateur courant, répertoire) vit dans ``ShellState`` : il évolue
avec ``cd`` et avec l'escalade de privilèges (US-04), ce qui rend les réponses
contextuelles (prompt, ``whoami``, ``pwd``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

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

_ETC_GROUP = """root:x:0:
sudo:x:27:admin,deploy
www-data:x:33:
postgres:x:120:
admin:x:1000:
deploy:x:1001:"""

_OS_RELEASE = """PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/\""""

_ETC_ISSUE = "Debian GNU/Linux 12 \\n \\l\n"
_ETC_HOSTNAME = "prod-srv-01"
_ETC_HOSTS = """127.0.0.1\tlocalhost
127.0.1.1\tprod-srv-01
10.0.2.15\tprod-srv-01

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters"""
_ETC_RESOLV = """nameserver 10.0.2.3
nameserver 8.8.8.8
search localdomain"""
_ETC_CRONTAB = """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily
0  2	* * *	root	/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1"""

# Kernel cohérent avec Debian 12 bookworm (série 6.1.x), pas 5.10 (= bullseye).
_UNAME = (
    "Linux prod-srv-01 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC "
    "Debian 6.1.90-1 (2024-05-03) x86_64 GNU/Linux"
)
_PROC_VERSION = (
    "Linux version 6.1.0-21-amd64 (debian-kernel@lists.debian.org) "
    "(gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) "
    "#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)"
)

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

_LSCPU = """Architecture:            x86_64
  CPU op-mode(s):        32-bit, 64-bit
  Byte Order:            Little Endian
CPU(s):                  4
  On-line CPU(s) list:   0-3
Vendor ID:               GenuineIntel
  Model name:            Intel(R) Xeon(R) Silver 4210 CPU @ 2.20GHz
    CPU family:          6
    Model:               85
    Thread(s) per core:  1
    Core(s) per socket:  4
    Socket(s):           1
    Stepping:            7
    BogoMIPS:            4400.00
Virtualization features:
  Hypervisor vendor:     KVM
  Virtualization type:   full"""

_IP_ADDR = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 52:54:00:8a:3c:1e brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::5054:ff:fe8a:3c1e/64 scope link
       valid_lft forever preferred_lft forever"""

_IP_ROUTE = """default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15"""

_IFCONFIG = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::5054:ff:fe8a:3c1e  prefixlen 64  scopeid 0x20<link>
        ether 52:54:00:8a:3c:1e  txqueuelen 1000  (Ethernet)
        RX packets 1843921  bytes 245829103 (234.4 MiB)
        TX packets 1502847  bytes 198273645 (189.0 MiB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)"""

_HOSTNAMECTL = """ Static hostname: prod-srv-01
       Icon name: computer-vm
         Chassis: vm
      Machine ID: 9f3c2b1a4d5e4f6a8b7c0d1e2f3a4b5c
         Boot ID: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
  Virtualization: kvm
Operating System: Debian GNU/Linux 12 (bookworm)
          Kernel: Linux 6.1.0-21-amd64
    Architecture: x86-64"""

_LSB_RELEASE = """Distributor ID:\tDebian
Description:\tDebian GNU/Linux 12 (bookworm)
Release:\t12
Codename:\tbookworm"""

# Appât : laisse croire à l'attaquant qu'il peut tout faire en sudo (US-04).
_SUDO_L = """Matching Defaults entries for admin on prod-srv-01:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin

User admin may run the following commands on prod-srv-01:
    (ALL : ALL) ALL"""

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
reboot   system boot  6.1.0-21-amd64   Wed Jan 31 11:18   still running

wtmp begins Wed Jan 31 11:18:02 2024"""

# --- arborescence simulée (ls conscient du chemin) --------------------------
# Listings courts (ls) par chemin absolu. Le home de l'utilisateur courant est
# résolu dynamiquement vers la clé "~HOME~".
_DIR_PLAIN = {
    "/": "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  "
    "run  sbin  srv  sys  tmp  usr  var",
    "/home": "admin  deploy",
    "/tmp": ".ICE-unix  .X11-unix  systemd-private-8f3c2b",  # nosec B108 - sortie ls forgée
    "/var": "backups  cache  lib  local  lock  log  mail  opt  run  spool  tmp  www",
    "/var/www": "app  html",
    "/var/log": "auth.log  btmp  daemon.log  dmesg  nginx  postgresql  syslog  wtmp",
    "/etc": "apt  cron.d  crontab  fstab  group  hostname  hosts  network  nginx  "
    "os-release  passwd  postgresql  resolv.conf  ssh  ssl  sudoers  systemd",
    "~HOME~": "app  backup.tar.gz  notes.txt",
    "~HOME~/app": "config.yml  docker-compose.yml  README.md  logs  src",
    "/var/www/app": "config.yml  docker-compose.yml  README.md  logs  src",
}

_LS_HOME_LONG = """total 28
drwxr-xr-x 3 {user} {user} 4096 Jun  9 09:02 .
drwxr-xr-x 4 root  root  4096 Jun  6 18:40 ..
-rw------- 1 {user} {user}  220 Jun  6 18:40 .bash_history
-rw-r--r-- 1 {user} {user} 3526 Jun  6 18:40 .bashrc
drwxr-xr-x 6 {user} {user} 4096 Jun  9 09:01 app
-rw-r--r-- 1 {user} {user} 8192 Jun  6 18:41 backup.tar.gz
-rw-r--r-- 1 {user} {user}  142 Jun  6 18:41 notes.txt"""

_LS_ROOT_LONG = """total 84
drwxr-xr-x  18 root root  4096 Jan 31 11:18 .
drwxr-xr-x  18 root root  4096 Jan 31 11:18 ..
drwxr-xr-x   2 root root  4096 Jan 27 09:14 bin
drwxr-xr-x   3 root root  4096 Jan 31 11:17 boot
drwxr-xr-x  17 root root  3260 Jun  9 09:01 dev
drwxr-xr-x  98 root root  4096 Jun  9 09:01 etc
drwxr-xr-x   4 root root  4096 Jan 31 11:16 home
drwxr-xr-x   2 root root  4096 Jun  6 18:40 root
drwxr-xr-x  12 root root  4096 Jan 31 11:18 var
drwxr-xr-x  14 root root  4096 Jan 27 09:14 usr
drwxrwxrwt   8 root root  4096 Jun  9 09:13 tmp"""

# Binaires "présents" pour `which` / `command -v`.
_BINARIES = {
    "ls": "/usr/bin/ls", "cat": "/usr/bin/cat", "bash": "/usr/bin/bash",
    "sh": "/usr/bin/sh", "python3": "/usr/bin/python3", "curl": "/usr/bin/curl",
    "wget": "/usr/bin/wget", "nc": "/usr/bin/nc", "perl": "/usr/bin/perl",
    "ssh": "/usr/bin/ssh", "scp": "/usr/bin/scp", "git": "/usr/bin/git",
    "docker": "/usr/bin/docker", "psql": "/usr/bin/psql", "vi": "/usr/bin/vi",
    "vim": "/usr/bin/vim", "grep": "/usr/bin/grep", "ps": "/usr/bin/ps",
    "id": "/usr/bin/id", "sudo": "/usr/bin/sudo", "su": "/usr/bin/su",
    "ip": "/usr/sbin/ip", "ifconfig": "/usr/sbin/ifconfig",
    "systemctl": "/usr/bin/systemctl", "apt": "/usr/bin/apt",
    "tar": "/usr/bin/tar", "gzip": "/usr/bin/gzip",
}

# Commandes qui réussissent sans rien afficher (ops fichiers / shell).
_SILENT_OK = {
    "mkdir", "rmdir", "touch", "rm", "cp", "mv", "ln", "chmod", "chown",
    "chgrp", "kill", "killall", "pkill", "export", "unset", "umask",
    "alias", "unalias", "true", "sync", "clear", "cd",
}

# Utilitaires texte : on renvoie une sortie vide plausible (plutôt que
# "command not found", qui trahirait le honeypot).
_EMPTY_OK = {
    "grep", "egrep", "fgrep", "find", "awk", "sed", "wc", "sort", "uniq",
    "cut", "tr", "xargs", "tail", "head", "more", "less", "tee", "diff",
}

_VAR_RE = re.compile(r"\$\?|\$\{(\w+)\}|\$(\w+)")


@dataclass
class ShellState:
    """État courant de la session shell (contexte des réponses)."""

    hostname: str = "prod-srv-01"
    user: str = "admin"
    cwd: str = "/home/admin"
    is_root: bool = False

    @property
    def home(self) -> str:
        return "/root" if self.is_root else f"/home/{self.user}"

    def prompt(self) -> str:
        """Prompt réaliste : ``$`` pour un user, ``#`` pour root."""
        symbol = "#" if self.is_root else "$"
        location = "~" if self.cwd == self.home else self.cwd
        return f"{self.user}@{self.hostname}:{location}{symbol} "

    def escalate_to_root(self) -> None:
        """Passe la session en contexte root (appelé après une escalade réussie)."""
        self.user = "root"
        self.is_root = True
        self.cwd = "/root"

    def env(self) -> dict[str, str]:
        """Environnement forgé (jamais le vrai env du process)."""
        return {
            "HOME": self.home,
            "USER": self.user,
            "LOGNAME": self.user,
            "SHELL": "/bin/bash",
            "PWD": self.cwd,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOSTNAME": self.hostname,
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
            "UID": "0" if self.is_root else "1000",
            "MAIL": f"/var/mail/{self.user}",
        }


def _id_line(state: ShellState) -> str:
    if state.is_root:
        return "uid=0(root) gid=0(root) groups=0(root)"
    return f"uid=1000({state.user}) gid=1000({state.user}) groups=1000({state.user}),27(sudo)"


def _expand(state: ShellState, text: str) -> str:
    """Expande les variables d'environnement comme bash (``echo $HOME``)."""
    env = state.env()

    def repl(match: re.Match[str]) -> str:
        if match.group(0) == "$?":
            return "0"
        name = match.group(1) or match.group(2)
        return env.get(name, "")

    return _VAR_RE.sub(repl, text)


def _resolve(state: ShellState, target: str) -> str:
    """Résout un chemin (relatif/~/.. ) en chemin absolu normalisé."""
    if not target or target == "~":
        return state.home
    if target.startswith("~"):
        target = state.home + target[1:]
    base = target if target.startswith("/") else f"{state.cwd.rstrip('/')}/{target}"
    parts: list[str] = []
    for segment in base.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    return "/" + "/".join(parts)


def _dir_key(state: ShellState, path: str) -> str:
    """Ramène le home courant sur la clé symbolique ``~HOME~`` du catalogue."""
    if path == state.home:
        return "~HOME~"
    if path.startswith(state.home + "/"):
        return "~HOME~" + path[len(state.home):]
    return path


def _ls(state: ShellState, args: list[str]) -> str:
    flags = "".join(a[1:] for a in args if a.startswith("-"))
    paths = [a for a in args if not a.startswith("-")]
    target = _resolve(state, paths[0]) if paths else state.cwd
    key = _dir_key(state, target)
    long = "l" in flags

    if long and key in ("~HOME~",):
        return _LS_HOME_LONG.format(user=state.user)
    if long and key == "/":
        return _LS_ROOT_LONG
    if key == "/root" and not state.is_root:
        return "ls: cannot open directory '/root': Permission denied"
    if key in _DIR_PLAIN:
        listing = _DIR_PLAIN[key]
        if long:
            # Listing long générique à partir des noms (suffisant pour les bots).
            names = listing.split()
            header = f"total {len(names) * 4}\n"
            return header + "\n".join(
                f"drwxr-xr-x 2 root root 4096 Jun  9 09:01 {n}" for n in names
            )
        return listing
    # Chemin non modélisé : on reste crédible avec un répertoire vide.
    return ""


def _which(args: list[str]) -> str:
    out = [_BINARIES[a] for a in args if a in _BINARIES]
    return "\n".join(out)


def _sim_wget(args: list[str]) -> str:
    """Simule une sortie wget crédible (US-05 : capture l'intention de download)."""
    url = next((a for a in args if a.startswith(("http://", "https://", "ftp://"))), "")
    out = url.rsplit("/", 1)[-1] or "index.html"
    if "-O" in args:
        idx = args.index("-O")
        if idx + 1 < len(args):
            out = args[idx + 1].rsplit("/", 1)[-1]
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    host = re.sub(r"^\w+://", "", url).split("/")[0] or "server"
    return (
        f"--{ts}--  {url}\n"
        f"Resolving {host}... 93.184.216.34\n"
        f"Connecting to {host}|93.184.216.34|:80... connected.\n"
        "HTTP request sent, awaiting response... 200 OK\n"
        "Length: 3287 (3.2K) [application/octet-stream]\n"
        f"Saving to: '{out}'\n\n"
        f"{out}          100%[===================>]   3.21K  --.-KB/s    in 0s\n\n"
        f"{ts} (24.8 MB/s) - '{out}' saved [3287/3287]"
    )


def _sim_curl(args: list[str]) -> str:
    """Simule curl : progression si -o/-O, sinon corps minimal."""
    if "-s" in args or "--silent" in args:
        return ""
    if "-O" in args or "-o" in args:
        return (
            "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
            "                                 Dload  Upload   Total   Spent    Left  Speed\n"
            "100  3287  100  3287    0     0  64231      0 --:--:-- --:--:-- --:--:-- 64450"
        )
    return ""


def run_command(state: ShellState, line: str) -> str:
    """Exécute (simule) une commande et renvoie sa sortie texte.

    L'appelant gère la journalisation, le jitter et la détection ; cette
    fonction ne produit que la sortie visible par l'attaquant. Une commande
    réellement inconnue renvoie le message ``command not found`` de bash.
    """
    line = line.strip()
    if not line:
        return ""

    parts = line.split()
    cmd = parts[0]
    args = parts[1:]

    # --- cd : met à jour l'état, pas de sortie ------------------------------
    if cmd == "cd":
        state.cwd = _resolve(state, args[0] if args else "")
        return ""

    # --- identité / système -------------------------------------------------
    if cmd == "pwd":
        return state.cwd
    if cmd == "whoami":
        return state.user
    if cmd == "id":
        return _id_line(state)
    if cmd in ("hostname",):
        return state.hostname
    if cmd == "hostnamectl":
        return _HOSTNAMECTL
    if cmd == "uname":
        return _UNAME if "-a" in args else "Linux"
    if cmd == "arch":
        return "x86_64"
    if cmd == "nproc":
        return "4"
    if cmd == "lscpu":
        return _LSCPU
    if cmd == "lsb_release":
        return _LSB_RELEASE
    if cmd == "uptime":
        return " 09:14:02 up 129 days,  3:56,  1 user,  load average: 0.08, 0.03, 0.01"
    if cmd == "date":
        return datetime.now(UTC).strftime("%a %b %e %H:%M:%S %Z %Y")
    if cmd == "history":
        return "\n".join(f"{i:5d}  {c}" for i, c in enumerate(_HISTORY, start=1))

    # --- processus / réseau -------------------------------------------------
    if cmd == "ps":
        return _PS_AUX
    if cmd == "top":
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
    if cmd == "free":
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:            3936         812        2103          12        1020        2884\n"
            "Swap:            974           0         974"
        )
    if cmd == "ip":
        if args and args[0] in ("a", "addr", "address"):
            return _IP_ADDR
        if args and args[0] in ("r", "route"):
            return _IP_ROUTE
        return 'Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }'
    if cmd == "ifconfig":
        return _IFCONFIG
    if cmd in ("route", "netstat-r"):
        return _IP_ROUTE

    # --- env / variables : sorties forgées ----------------------------------
    if cmd in ("env", "printenv", "set") and not args:
        return "\n".join(f"{k}={v}" for k, v in state.env().items())
    if cmd == "printenv" and args:
        return state.env().get(args[0], "")

    # --- which / command ----------------------------------------------------
    if cmd == "which":
        return _which(args)
    if cmd == "command" and args[:1] == ["-v"]:
        return _which(args[1:])

    # --- python : python3 présent, python (sans suffixe) absent -------------
    if cmd == "python3":
        return "Python 3.11.2" if ("--version" in args or "-V" in args) else ""

    # --- sudo (hors escalade, traitée côté serveur) -------------------------
    if cmd == "sudo":
        if not args:
            return "usage: sudo -h | -V | -l | -v | command"
        if args[0] == "-l":
            return _SUDO_L  # appât : (ALL : ALL) ALL
        if args[0] in ("-v", "-k", "-n", "-K"):
            return ""
        # sudoers autorise tout : on exécute la commande sous-jacente.
        return run_command(state, " ".join(args))

    # --- cat / fichiers -----------------------------------------------------
    if cmd in ("cat", "more", "less", "head", "tail"):
        if not args:
            return ""
        known = _cat(args)
        if known is not None:
            return known
        target = next((a for a in args if not a.startswith("-")), "")
        return f"{cmd}: {target}: No such file or directory"

    # --- ls -----------------------------------------------------------------
    if cmd in ("ls", "dir"):
        return _ls(state, args)

    # --- echo (avec expansion de variables) ---------------------------------
    if cmd == "echo":
        rest = line[len("echo"):].strip()
        if rest.startswith("-n "):
            rest = rest[3:]
        # bash expande les variables puis retire les guillemets.
        return _expand(state, rest).replace('"', "").replace("'", "")

    # --- downloads simulés --------------------------------------------------
    if cmd == "wget":
        return _sim_wget(args)
    if cmd == "curl":
        return _sim_curl(args)

    # --- ops fichiers / utilitaires : succès silencieux ---------------------
    if cmd in _SILENT_OK:
        return ""
    if cmd in _EMPTY_OK:
        return ""

    if cmd in ("exit", "logout"):
        return ""

    # --- commande réellement inconnue ---------------------------------------
    return f"bash: {cmd}: command not found"


def _cat(args: list[str]) -> str | None:
    """Réponses forgées pour ``cat`` des fichiers couramment sondés.

    Renvoie ``None`` si le fichier n'est pas reconnu comme "spécial" — l'appelant
    décide alors du comportement par défaut.
    """
    target = next((a for a in args if not a.startswith("-")), "")
    table = {
        "/etc/passwd": _ETC_PASSWD,
        "/etc/group": _ETC_GROUP,
        "/etc/os-release": _OS_RELEASE,
        "/etc/issue": _ETC_ISSUE,
        "/etc/hostname": _ETC_HOSTNAME,
        "/etc/hosts": _ETC_HOSTS,
        "/etc/resolv.conf": _ETC_RESOLV,
        "/etc/crontab": _ETC_CRONTAB,
        "/proc/cpuinfo": _CPUINFO,
        "/proc/version": _PROC_VERSION,
    }
    if target in table:
        return table[target]
    if target in ("/etc/shadow", "/etc/sudoers"):
        return f"cat: {target}: Permission denied"
    return None
