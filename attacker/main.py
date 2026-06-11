from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from attacker import __version__
from attacker.attacks import ftp_bruteforce, http_scan, ssh_bruteforce
from attacker.attacks.common import is_reachable, make_results_dir
from attacker.config import (
    DEFAULT_REPORTS_DIR,
    DEFAULT_TARGET,
)
from attacker.deps import check_for_command
from attacker.logging import setup_logging
from attacker.recon.port_scan import DEFAULT_PORTS, NmapError, discover_services

logger = logging.getLogger("attacker")

_SSH_FALLBACK_PORTS = (22, 2222)
_FTP_FALLBACK_PORTS = (21, 2121)
_HTTP_FALLBACK_PORTS = (80, 8080)


def _resolve_port(host: str, explicit: int | None, candidates: tuple[int, ...]) -> int:
    if explicit is not None:
        return explicit

    for port in candidates:
        if is_reachable(host, port):
            logger.info("Port autodiscovery: %s:%d reachable — using it", host, port)
            return port

    logger.warning(
        "Port autodiscovery: none of %s reachable on %s, defaulting to %d",
        list(candidates),
        host,
        candidates[-1],
    )
    return candidates[-1]


_EPILOG = """\
Examples:
  python -m attacker check
  python -m attacker http --target 10.13.0.10
  python -m attacker ftp  --log-api http://analyzer:8000
  python -m attacker all  --skip-ssh
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attacker",
        description="Honeypot validation attack toolkit (M1SPRO brick B10).",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"attacker {__version__}",
    )

    common = argparse.ArgumentParser(add_help=False)
    group = common.add_argument_group("Global options")
    group.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"target IP (default: {DEFAULT_TARGET})",
    )
    group.add_argument(
        "--reports-dir",
        default=DEFAULT_REPORTS_DIR,
        type=Path,
        metavar="DIR",
        help=f"output directory (default: {DEFAULT_REPORTS_DIR})",
    )
    group.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors",
    )
    group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase verbosity (-v for debug)",
    )
    group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress non-essential output",
    )
    group.add_argument(
        "--skip-dep-check",
        action="store_true",
        help="skip the dependency pre-flight check",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    # --- check ---
    p_check = sub.add_parser(
        "check",
        parents=[common],
        help="verify dependencies (binaries, wordlists, connectivity)",
    )
    p_check.add_argument(
        "--for",
        dest="check_for",
        default="check",
        choices=["check", "http", "ftp", "ssh", "all"],
        help="subset of dependencies to verify (default: check)",
    )
    p_check.add_argument(
        "--no-network",
        action="store_true",
        help="skip TCP reachability checks",
    )

    # --- http ---
    p_http = sub.add_parser(
        "http",
        parents=[common],
        help="HTTP scan (Nikto + dirsearch + targeted probes)",
    )
    p_http.add_argument(
        "--port",
        type=int,
        default=None,
        help="HTTP port",
    )
    p_http.add_argument("--nikto-timeout", type=int, default=120)
    p_http.add_argument("--dirsearch-wordlist", type=Path, default=None)
    p_http.add_argument("--max-login-attempts", type=int, default=40)
    p_http.add_argument("--skip-nikto", action="store_true")
    p_http.add_argument("--skip-dirsearch", action="store_true")
    p_http.add_argument("--password-wordlist", type=Path, default=None)
    p_http.add_argument("--username-wordlist", type=Path, default=None)
    p_http.add_argument(
        "--skip-login",
        action="store_true",
        help="skip phase 4 (CMS-aware / generic credential attacks)",
    )
    p_http.add_argument(
        "--pause",
        type=float,
        default=10.0,
        help="seconds to wait before running assertions",
    )

    # --- ftp ---
    p_ftp = sub.add_parser(
        "ftp",
        parents=[common],
        help="FTP brute-force (Hydra + anonymous + decoys)",
    )
    p_ftp.add_argument("--port", type=int, default=None, help="FTP port")
    p_ftp.add_argument("--hydra-tasks", type=int, default=16)
    p_ftp.add_argument(
        "--hydra-timeout",
        type=int,
        default=300,
        help="seconds before hydra is killed (0 = no limit, run the full wordlist)",
    )
    p_ftp.add_argument("--password-wordlist", type=Path, default=None)
    p_ftp.add_argument("--username-wordlist", type=Path, default=None)
    p_ftp.add_argument(
        "--default-credentials",
        type=Path,
        default=None,
        metavar="FILE",
        help="user:password list for the default-credential phase "
        "(default: SecLists ftp-betterdefaultpasslist)",
    )
    p_ftp.add_argument(
        "--full-wordlist",
        action="store_true",
        help="skip default credentials and brute-force with the large wordlist",
    )
    p_ftp.add_argument("--skip-hydra", action="store_true")
    p_ftp.add_argument("--skip-anonymous", action="store_true")
    p_ftp.add_argument("--skip-manual", action="store_true")
    p_ftp.add_argument("--pause", type=float, default=10.0)

    # --- ssh ---
    p_ssh = sub.add_parser(
        "ssh",
        parents=[common],
        help="SSH brute-force (delegates to attacker.attacks.ssh_bruteforce)",
    )
    p_ssh.add_argument("--port", type=int, default=None)
    p_ssh.add_argument("--hydra-tasks", type=int, default=16)
    p_ssh.add_argument(
        "--hydra-timeout",
        type=int,
        default=120,
        help="seconds before hydra is killed (0 = no limit, run the full wordlist)",
    )
    p_ssh.add_argument("--password-wordlist", type=Path, default=None)
    p_ssh.add_argument("--username-wordlist", type=Path, default=None)
    p_ssh.add_argument(
        "--default-credentials",
        type=Path,
        default=None,
        metavar="FILE",
        help="user:password list for the default-credential phase "
        "(default: SecLists ssh-betterdefaultpasslist)",
    )
    p_ssh.add_argument(
        "--full-wordlist",
        action="store_true",
        help="skip default credentials and brute-force with the large wordlist",
    )
    p_ssh.add_argument("--skip-hydra", action="store_true")
    p_ssh.add_argument("--skip-manual", action="store_true")

    # --- all ---
    p_all = sub.add_parser(
        "all",
        parents=[common],
        help="nmap service discovery, then attack each detected service",
    )
    p_all.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        metavar="SPEC",
        help=f"nmap port spec for discovery (default: {DEFAULT_PORTS})",
    )
    p_all.add_argument(
        "--nmap-timeout",
        type=int,
        default=120,
        help="seconds before the nmap discovery scan is aborted",
    )
    p_all.add_argument(
        "--http-port",
        type=int,
        default=None,
        help="force an HTTP attack on this port even if nmap misses it",
    )
    p_all.add_argument(
        "--ftp-port",
        type=int,
        default=None,
        help="force an FTP attack on this port even if nmap misses it",
    )
    p_all.add_argument(
        "--ssh-port",
        type=int,
        default=None,
        help="force an SSH attack on this port even if nmap misses it",
    )
    p_all.add_argument("--skip-http", action="store_true")
    p_all.add_argument("--skip-ftp", action="store_true")
    p_all.add_argument("--skip-ssh", action="store_true")
    p_all.add_argument(
        "--parallel",
        action="store_true",
        help="run the discovered campaigns concurrently instead of sequentially",
    )

    return parser


def _preflight(args: argparse.Namespace, command: str, ports: dict[str, int]) -> int:
    if args.skip_dep_check:
        logger.info("Dependency check skipped (--skip-dep-check)")
        return 0

    report = check_for_command(
        command,
        target=args.target,
        ports=ports,
        check_network=False,
    )
    if report.has_blocking:
        logger.error(
            "Blocking dependencies are missing; run 'attacker check' for details"
        )

        return 2

    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    ftp_port = _resolve_port(args.target, args.port, _FTP_FALLBACK_PORTS)
    ssh_port = _resolve_port(args.target, args.port, _SSH_FALLBACK_PORTS)
    ports = {
        "http": 80,
        "ftp": ftp_port,
        "ssh": ssh_port,
    }
    report = check_for_command(
        args.check_for,
        target=args.target,
        ports=ports,
        check_network=not args.no_network,
    )

    sections = (
        ("Python", "python"),
        ("Binaries", "binary"),
        ("Payloads", "payload"),
        ("Network", "network"),
    )
    for title, kind in sections:
        items = report.by_kind(kind)
        if not items:
            continue

        logger.info("================== %s ==================", title)
        for item in items:
            label = f"{item.name} — {item.used_for}" if item.used_for else item.name
            if item.ok:
                logger.info("OK    %s :: %s", label, item.detail)
            elif item.required:
                logger.error(
                    "FAIL  %s :: %s :: hint: %s",
                    label,
                    item.detail,
                    item.install_hint or "(no hint)",
                )
            else:
                logger.warning(
                    "WARN  %s :: %s :: hint: %s",
                    label,
                    item.detail,
                    item.install_hint or "(no hint)",
                )

    total = len(report.results)
    blocking = sum(1 for r in report.results if r.blocking)
    warnings = sum(1 for r in report.results if not r.ok and not r.required)
    logger.info(
        "Summary: %d total, %d blocking, %d warnings", total, blocking, warnings
    )

    return 1 if report.has_blocking else 0


def _cmd_http(args: argparse.Namespace) -> int:
    http_port = _resolve_port(args.target, args.port, _HTTP_FALLBACK_PORTS)
    rc = _preflight(args, "http", {"http": http_port})
    if rc != 0:
        return rc

    config = http_scan.HttpScanConfig(
        target_host=args.target,
        target_port=http_port,
        nikto_timeout=args.nikto_timeout,
        dirsearch_wordlist=args.dirsearch_wordlist,
        max_login_attempts=args.max_login_attempts,
        skip_nikto=args.skip_nikto,
        skip_dirsearch=args.skip_dirsearch,
        skip_login=args.skip_login,
        pause_before_assertions=args.pause,
        username_wordlist=args.username_wordlist,
        password_wordlist=args.password_wordlist,
    )
    report = http_scan.run(config, args.reports_dir)
    logger.info(
        "HTTP report: cms=%s (%d%%) version=%s login_attempts=%d "
        "credentials_found=%d sensitive_paths=%d nikto=%d findings=%d exit=%d",
        report.cms or "unknown",
        report.cms_confidence,
        report.cms_version or "?",
        report.login_attempts,
        report.credentials_found,
        report.sensitive_paths,
        report.nikto_findings,
        len(report.findings),
        report.exit_code,
    )
    return report.exit_code


def _cmd_ftp(args: argparse.Namespace) -> int:
    ftp_port = _resolve_port(args.target, args.port, _FTP_FALLBACK_PORTS)
    rc = _preflight(args, "ftp", {"ftp": ftp_port})
    if rc != 0:
        return rc

    config = ftp_bruteforce.FtpBruteforceConfig(
        target_host=args.target,
        target_port=ftp_port,
        hydra_tasks=args.hydra_tasks,
        hydra_timeout=args.hydra_timeout,
        password_wordlist=args.password_wordlist,
        username_wordlist=args.username_wordlist,
        default_credentials=args.default_credentials,
        use_full_wordlist=args.full_wordlist,
        skip_hydra=args.skip_hydra,
        skip_anonymous=args.skip_anonymous,
        pause_before_assertions=args.pause,
    )
    report = ftp_bruteforce.run(config, args.reports_dir)
    logger.info(
        "FTP report: hydra_attempts=%d credentials_found=%d decoys=%d exit=%d",
        report.hydra_attempts,
        report.hydra_credentials_found,
        report.decoys_downloaded,
        report.exit_code,
    )
    return report.exit_code


def _cmd_ssh(args: argparse.Namespace) -> int:
    ssh_port = _resolve_port(args.target, args.port, _SSH_FALLBACK_PORTS)
    rc = _preflight(args, "ssh", {"ssh": ssh_port})
    if rc != 0:
        return rc

    config = ssh_bruteforce.SshBruteforceConfig(
        target_host=args.target,
        target_port=ssh_port,
        hydra_tasks=args.hydra_tasks,
        hydra_timeout=args.hydra_timeout,
        password_wordlist=args.password_wordlist,
        username_wordlist=args.username_wordlist,
        default_credentials=args.default_credentials,
        use_full_wordlist=args.full_wordlist,
        skip_hydra=args.skip_hydra,
    )
    report = ssh_bruteforce.run(config, args.reports_dir)
    logger.info(
        "SSH report: hydra_attempts=%d credentials_found=%d exit=%d",
        report.hydra_attempts,
        report.hydra_credentials_found,
        report.exit_code,
    )
    return report.exit_code


@dataclass
class _CampaignOutcome:
    name: str
    exit_code: int
    duration_s: float
    skipped: bool = False


def _attack_http(target: str, port: int, reports_dir: Path) -> int:
    return http_scan.run(
        http_scan.HttpScanConfig(
            target_host=target,
            target_port=port,
        ),
        reports_dir,
    ).exit_code


def _attack_ftp(target: str, port: int, reports_dir: Path) -> int:
    return ftp_bruteforce.run(
        ftp_bruteforce.FtpBruteforceConfig(
            target_host=target,
            target_port=port,
        ),
        reports_dir,
    ).exit_code


def _attack_ssh(target: str, port: int, reports_dir: Path) -> int:
    return ssh_bruteforce.run(
        ssh_bruteforce.SshBruteforceConfig(
            target_host=target,
            target_port=port,
        ),
        reports_dir,
    ).exit_code


# category -> (runner, --skip-<x> attr, --<x>-port override attr)
_CAMPAIGNS: dict[str, tuple[Callable[[str, int, Path], int], str, str]] = {
    "http": (_attack_http, "skip_http", "http_port"),
    "ftp": (_attack_ftp, "skip_ftp", "ftp_port"),
    "ssh": (_attack_ssh, "skip_ssh", "ssh_port"),
}


def _plan_campaigns(
    args: argparse.Namespace,
    discovered: dict[str, list[int]],
) -> list[tuple[str, int]]:
    """Decide which (category, port) attacks to run.

    A forced --<x>-port always runs, even if nmap missed the service; otherwise
    every nmap-detected port for a non-skipped category is attacked.
    """
    plan: list[tuple[str, int]] = []
    for category, (_, skip_attr, port_attr) in _CAMPAIGNS.items():
        if getattr(args, skip_attr):
            logger.warning("%s campaign skipped (--skip-%s)", category, category)
            continue

        override: int | None = getattr(args, port_attr)
        if override is not None:
            plan.append((category, override))
            continue

        ports = discovered.get(category, [])
        if not ports:
            logger.info("%s: no service detected by nmap, nothing to attack", category)
            continue
        for port in ports:
            plan.append((category, port))
    return plan


def _run_campaign(
    category: str,
    port: int,
    target: str,
    reports_dir: Path,
) -> _CampaignOutcome:
    runner = _CAMPAIGNS[category][0]
    label = f"{category}:{port}"
    logger.info("================== Campaign %s ==================", label)
    t0 = time.monotonic()
    exit_code = runner(target, port, reports_dir)
    return _CampaignOutcome(label, exit_code, time.monotonic() - t0)


def _cmd_all(args: argparse.Namespace) -> int:
    rc = _preflight(args, "all", {})
    if rc != 0:
        return rc

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    consolidated = args.reports_dir / f"all-{timestamp}"
    consolidated.mkdir(parents=True, exist_ok=True)
    logger.info("Consolidated artefacts: %s", consolidated)

    recon_results = make_results_dir(consolidated, prefix="recon")
    try:
        services = discover_services(
            args.target,
            ports=args.ports,
            timeout=args.nmap_timeout,
            results=recon_results,
        )
    except NmapError as exc:
        logger.error("Service discovery failed: %s", exc)
        return 2

    discovered: dict[str, list[int]] = {}
    for svc in services:
        category = svc.attack
        if category is None:
            logger.info(
                "nmap: %s on port %d has no associated attack, skipping",
                svc.service,
                svc.port,
            )
            continue
        discovered.setdefault(category, []).append(svc.port)

    plan = _plan_campaigns(args, discovered)
    if not plan:
        logger.warning("No attackable service to run against %s", args.target)

    start = time.monotonic()
    if args.parallel and len(plan) > 1:
        logger.info("Running %d campaigns in parallel", len(plan))
        with ThreadPoolExecutor(max_workers=len(plan)) as pool:
            futures = [
                pool.submit(_run_campaign, category, port, args.target, consolidated)
                for category, port in plan
            ]
            outcomes = [future.result() for future in futures]
    else:
        outcomes = [
            _run_campaign(category, port, args.target, consolidated)
            for category, port in plan
        ]

    duration = time.monotonic() - start
    failed = sum(1 for o in outcomes if not o.skipped and o.exit_code != 0)

    logger.info("Campaign duration: %.1fs", duration)
    for outcome in outcomes:
        status = (
            "SKIP"
            if outcome.skipped
            else ("PASS" if outcome.exit_code == 0 else "FAIL")
        )
        logger.info(
            "Campaign %-4s : %s (rc=%d, %.1fs)",
            outcome.name,
            status,
            outcome.exit_code,
            outcome.duration_s,
        )

    summary = consolidated / "summary.txt"
    summary.write_text(
        "target: {target}\n"
        "duration_s: {duration:.1f}\n"
        "{lines}\n"
        "failed: {failed}\n".format(
            target=args.target,
            duration=duration,
            lines="\n".join(
                f"{o.name}: rc={o.exit_code} duration={o.duration_s:.1f}s "
                f"skipped={o.skipped}"
                for o in outcomes
            ),
            failed=failed,
        ),
        encoding="utf-8",
    )
    return 0 if failed == 0 else 1


_HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "check": _cmd_check,
    "http": _cmd_http,
    "ftp": _cmd_ftp,
    "ssh": _cmd_ssh,
    "all": _cmd_all,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    verbosity = -1 if args.quiet else args.verbose
    setup_logging(verbosity=verbosity, no_color=args.no_color)

    handler = _HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    try:
        return handler(args)
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
