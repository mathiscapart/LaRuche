from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from attacker.attacks.common import ResultsDir, run_command

logger = logging.getLogger(__name__)

__all__ = [
    "DiscoveredService",
    "NmapError",
    "DEFAULT_PORTS",
    "SERVICE_TO_ATTACK",
    "discover_services",
    "classify",
]

# Standard ports plus the alternate ports the lab honeypots bind to.
DEFAULT_PORTS = "21,22,80,443,2121,2222,8000,8080,8443"

# Maps an nmap service name to the attack category we know how to run.
SERVICE_TO_ATTACK: dict[str, str] = {
    "ssh": "ssh",
    "ftp": "ftp",
    "ftp-data": "ftp",
    "http": "http",
    "https": "http",
    "http-proxy": "http",
    "http-alt": "http",
}


class NmapError(RuntimeError):
    """Raised when nmap is missing or the scan could not be completed."""


@dataclass(frozen=True)
class DiscoveredService:
    port: int
    service: str
    version: str = ""

    @property
    def attack(self) -> str | None:
        return classify(self.service)


def classify(service: str) -> str | None:
    """Return the attack category for an nmap service name, or None."""
    return SERVICE_TO_ATTACK.get(service.strip().lower())


def _parse_greppable(stdout: str) -> list[DiscoveredService]:
    """Parse `nmap -oG -` output into the list of open services.

    Greppable port fields look like:
        22/open/tcp//ssh//OpenSSH 8.2//
    i.e. port/state/proto/owner/service/rpc/version/.
    """
    services: list[DiscoveredService] = []
    seen: set[int] = set()
    for line in stdout.splitlines():
        if "Ports:" not in line:
            continue
        _, _, ports_blob = line.partition("Ports:")
        ports_blob = ports_blob.split("Ignored State:", 1)[0]
        for entry in ports_blob.split(","):
            fields = entry.strip().split("/")
            if len(fields) < 5 or fields[1] != "open":
                continue
            try:
                port = int(fields[0])
            except ValueError:
                continue
            if port in seen:
                continue
            seen.add(port)
            services.append(
                DiscoveredService(
                    port=port,
                    service=fields[4],
                    version=fields[6] if len(fields) > 6 else "",
                )
            )
    return services


def discover_services(
    host: str,
    *,
    ports: str = DEFAULT_PORTS,
    timeout: int = 120,
    results: ResultsDir | None = None,
) -> list[DiscoveredService]:
    """Run nmap service detection against `host` and return open services.

    Raises NmapError if the nmap binary is missing or the scan times out so
    the caller can fail fast (strict dependency).
    """
    log_to: Path | None = results.file("nmap.log") if results is not None else None
    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-p",
        ports,
        "-oG",
        "-",
        host,
    ]
    logger.info("nmap service discovery against %s (ports=%s)", host, ports)
    result = run_command(cmd, timeout=timeout + 10, log_to=log_to)

    if result.return_code == 127:
        raise NmapError("nmap binary not found (install pkg 'nmap')")
    if result.timed_out:
        raise NmapError(f"nmap timed out after {timeout}s scanning {host}")
    if result.return_code != 0:
        raise NmapError(
            f"nmap exited with rc={result.return_code}: "
            f"{result.stderr.strip() or 'unknown error'}"
        )

    services = _parse_greppable(result.stdout)
    logger.info(
        "nmap found %d open service(s): %s",
        len(services),
        ", ".join(f"{s.service}:{s.port}" for s in services) or "(none)",
    )
    return services
