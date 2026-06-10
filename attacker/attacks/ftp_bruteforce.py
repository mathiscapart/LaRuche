from __future__ import annotations

import ftplib
import logging
from dataclasses import dataclass, field
from pathlib import Path

from attacker.attacks.common import (
    ResultsDir,
    ensure_allowed,
    is_reachable,
    make_results_dir,
    resolve_password_wordlist,
    resolve_username_wordlist,
    run_hydra,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FtpBruteforceConfig:
    target_host: str
    target_port: int = 2121
    hydra_tasks: int = 8
    hydra_timeout: int = 300
    ftp_timeout: float = 10.0
    pause_between_manual: float = 0.3
    pause_before_assertions: float = 10.0
    skip_hydra: bool = False
    skip_anonymous: bool = False
    bypass_allowlist: bool = False
    password_wordlist: Path | None = None
    username_wordlist: Path | None = None


@dataclass
class FtpBruteforceReport:
    target: str
    hydra_attempts: int = 0
    hydra_credentials_found: int = 0
    anonymous_connected: bool = False
    decoys_downloaded: int = 0
    skipped_phases: list[str] = field(default_factory=list)
    exit_code: int = 0


def _phase_anonymous(
    config: FtpBruteforceConfig,
    results: ResultsDir,
) -> tuple[bool, int]:
    log_lines: list[str] = []
    connected = False
    decoys_downloaded = 0

    try:
        client = ftplib.FTP()
        client.connect(
            config.target_host,
            config.target_port,
            timeout=config.ftp_timeout,
        )
        log_lines.append(f"CONNECT {config.target_host}:{config.target_port} -> OK")

        try:
            client.login("anonymous", "anonymous@example.com")
            log_lines.append("LOGIN anonymous -> ACCEPTED")
            logger.info("Anonymous login accepted")
            connected = True
        except ftplib.error_perm as exc:
            log_lines.append(f"LOGIN anonymous -> REFUSED ({exc})")
            logger.info("Anonymous login refused (%s)", exc)

        try:
            client.quit()
        except ftplib.all_errors:
            pass

    except (OSError, ftplib.all_errors) as exc:
        log_lines.append(f"CONNECT -> FAIL ({exc})")
        logger.error("FTP connection failed: %s", exc)

    results.file("anonymous.txt").write_text("\n".join(log_lines), encoding="utf-8")
    return connected, decoys_downloaded


def run(
    config: FtpBruteforceConfig,
    reports_dir: Path,
) -> FtpBruteforceReport:
    report = FtpBruteforceReport(
        target=f"ftp://{config.target_host}:{config.target_port}"
    )

    if not ensure_allowed(config.target_host, bypass=config.bypass_allowlist):
        report.exit_code = 2
        return report

    results = make_results_dir(reports_dir, prefix="ftp")
    logger.info("Artefacts directory: %s", results.path)

    if not is_reachable(config.target_host, config.target_port):
        logger.error(
            "FTP honeypot unreachable at %s:%d",
            config.target_host,
            config.target_port,
        )
        report.exit_code = 2
        return report
    logger.info("FTP honeypot reachable")

    username_wordlist = resolve_username_wordlist(config.username_wordlist)
    password_wordlist = resolve_password_wordlist(config.password_wordlist)

    if config.skip_hydra:
        report.skipped_phases.append("hydra")
        logger.warning("Phase 1 skipped (--skip-hydra)")
    elif password_wordlist is None:
        logger.error("No password wordlist available; skipping hydra phase")
        report.skipped_phases.append("hydra")
    elif username_wordlist is None:
        logger.error("No username wordlist available; skipping hydra phase")
        report.skipped_phases.append("hydra")
    else:
        report.hydra_attempts, report.hydra_credentials_found = run_hydra(
            "ftp",
            config.target_host,
            config.target_port,
            config.hydra_tasks,
            config.hydra_timeout,
            username_wordlist,
            password_wordlist,
            results,
        )

    if config.skip_anonymous:
        report.skipped_phases.append("anonymous")
        logger.warning("Phase 2 skipped (--skip-anonymous)")
    else:
        report.anonymous_connected, report.decoys_downloaded = _phase_anonymous(
            config, results
        )

    _write_summary(results, report)
    return report


def _write_summary(results: ResultsDir, report: FtpBruteforceReport) -> None:
    summary = results.file("summary.txt")
    lines = [
        f"target: {report.target}",
        f"hydra_attempts: {report.hydra_attempts}",
        f"hydra_credentials_found: {report.hydra_credentials_found}",
        f"anonymous_connected: {report.anonymous_connected}",
        f"decoys_downloaded: {report.decoys_downloaded}",
        f"skipped_phases: {','.join(report.skipped_phases) or 'none'}",
        f"exit_code: {report.exit_code}",
    ]
    summary.write_text("\n".join(lines), encoding="utf-8")
