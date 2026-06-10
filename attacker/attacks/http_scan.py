"""Professional HTTP scan pipeline (M1SPRO brick B10).

Phases:
  1. Nikto            — broad vulnerability scan (optional, external tool).
  2. dirsearch        — content discovery (optional, external tool).
  3. Fingerprint      — identify the CMS / server / stack (web_fingerprint).
  4. Targeted attack  — CMS-aware login + recon when a CMS is detected
                        (web_attacks.attack_cms), otherwise a generic
                        discovery + credential spray (web_attacks.attack_generic).

The fingerprint decides phase 4, so the scan adapts to the target instead of
firing the same payloads everywhere.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from attacker.attacks.common import (
    HttpResponse,
    ResultsDir,
    http_request,
    make_results_dir,
    run_command,
    resolve_username_wordlist,
    resolve_password_wordlist,
)
from attacker.attacks.web_attacks import (
    AttackOutcome,
    Finding,
    attack_cms,
    attack_generic,
)
from attacker.attacks.web_fingerprint import Fingerprint, fingerprint
from attacker.config import (
    PAYLOAD_HTTP_INJECTIONS,
    PAYLOAD_HTTP_PATHS,
    load_lines,
)
from attacker.wordlists import ensure_dirsearch_wordlist

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HttpScanConfig:
    target_host: str
    target_port: int = 80
    nikto_timeout: int = 120
    dirsearch_threads: int = 10
    dirsearch_timeout: int = 180
    request_timeout: float = 10.0
    pause_between_probes: float = 0.3
    pause_before_assertions: float = 10.0
    max_login_attempts: int = 40
    skip_nikto: bool = False
    skip_dirsearch: bool = False
    skip_login: bool = False
    dirsearch_wordlist: Path | None = None
    password_wordlist: Path | None = None
    username_wordlist: Path | None = None

    @property
    def base_url(self) -> str:
        if self.target_port == 443:
            return f"https://{self.target_host}"

        if self.target_port == 80:
            return f"http://{self.target_host}"

        return f"http://{self.target_host}:{self.target_port}"


@dataclass
class HttpScanReport:
    target: str
    cms: str = ""
    cms_version: str = ""
    cms_confidence: int = 0
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    nikto_findings: int = 0
    login_attempts: int = 0
    credentials_found: int = 0
    sensitive_paths: int = 0
    findings: list[Finding] = field(default_factory=list)
    skipped_phases: list[str] = field(default_factory=list)
    exit_code: int = 0


def _phase_nikto(config: HttpScanConfig, results: ResultsDir) -> int:
    output_csv = results.file("nikto")
    output_txt = results.file("nikto.log")
    cmd = [
        "nikto",
        "-h",
        config.base_url,
        "-o",
        str(output_csv),
        "-Format",
        "csv",
        "-Tuning",
        "1234567890abcde",
        "-nointeractive",
        "-maxtime",
        f"{config.nikto_timeout}s",
    ]
    logger.info("Phase 1: Nikto against %s", config.base_url)

    result = run_command(cmd, timeout=config.nikto_timeout + 10, log_to=output_txt)
    if result.return_code == 127:
        logger.error("nikto binary not found — skipping phase 1")
        return 0

    findings = 0
    if output_csv.exists():
        prefix = f'"{config.target_host}'
        findings = sum(
            1
            for line in output_csv.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
            if line.startswith(prefix)
        )
    logger.info("Nikto completed in %.1fs (%d findings)", result.duration_s, findings)

    return findings


def _locate_dirsearch() -> list[str] | None:
    if shutil.which("dirsearch"):
        return ["dirsearch"]

    for alt in ("/usr/share/dirsearch/dirsearch.py", "/opt/dirsearch/dirsearch.py"):
        if Path(alt).is_file():
            return ["python3", alt]

    return None


def _phase_dirsearch(config: HttpScanConfig, results: ResultsDir) -> bool:
    command_prefix = _locate_dirsearch()
    if command_prefix is None:
        logger.warning("dirsearch not found — phase 2 skipped")
        return False

    wordlist = config.dirsearch_wordlist or ensure_dirsearch_wordlist()
    if wordlist is None:
        logger.warning("No dirsearch wordlist available — phase 2 skipped")
        return False

    output_json = results.file("dirsearch.json")
    output_log = results.file("dirsearch.log")
    cmd = [
        *command_prefix,
        "-u",
        config.base_url,
        "-w",
        str(wordlist),
        "-t",
        str(config.dirsearch_threads),
        "--timeout",
        str(int(config.request_timeout)),
        "-o",
        str(output_json),
        "-O",
        "json",
    ]
    logger.info("Phase 2: dirsearch (wordlist=%s)", wordlist)
    result = run_command(cmd, timeout=config.dirsearch_timeout, log_to=output_log)
    logger.info(
        "dirsearch completed in %.1fs (rc=%d)", result.duration_s, result.return_code
    )
    return True


def _phase_fingerprint(
    config: HttpScanConfig,
    results: ResultsDir,
    home: HttpResponse,
) -> Fingerprint:
    logger.info("Phase 3: fingerprinting %s", config.base_url)
    fp = fingerprint(
        config.base_url,
        request_timeout=config.request_timeout,
        pause=config.pause_between_probes,
        home=home,
    )
    lines = [
        f"target: {config.base_url}",
        f"cms: {fp.cms or 'unknown'}",
        f"cms_confidence: {fp.cms_confidence}%",
        f"cms_version: {fp.cms_version or 'unknown'}",
        f"hosted_platform: {fp.hosted}",
        f"server: {fp.server or 'unknown'}",
        f"x_powered_by: {fp.powered_by or 'unknown'}",
        f"title: {fp.title or '-'}",
        f"technologies: {', '.join(fp.technologies) or '-'}",
        "",
        "# evidence",
        *fp.evidence,
    ]
    results.file("fingerprint.txt").write_text("\n".join(lines), encoding="utf-8")
    return fp


def _load_payload_lines(path: Path) -> list[str]:
    try:
        return load_lines(path)
    except FileNotFoundError:
        logger.warning("Payload file missing (%s) — using built-in defaults only", path)
        return []


def _build_credentials(config: HttpScanConfig) -> list[tuple[str, str]]:
    """Pair every username with every password from the resolved wordlists,
    capped at ``max_login_attempts`` candidate pairs."""
    username_wordlist = resolve_username_wordlist(config.username_wordlist)
    password_wordlist = resolve_password_wordlist(config.password_wordlist)

    usernames = _load_payload_lines(username_wordlist) if username_wordlist else []
    passwords = _load_payload_lines(password_wordlist) if password_wordlist else []

    if not usernames or not passwords:
        logger.warning(
            "Missing username/password wordlist — credential spray will be empty"
        )
        return []

    credentials: list[tuple[str, str]] = []
    for user in usernames:
        for password in passwords:
            credentials.append((user, password))
            if len(credentials) >= config.max_login_attempts:
                return credentials

    return credentials


def _phase_attack(
    config: HttpScanConfig,
    results: ResultsDir,
    fp: Fingerprint,
) -> AttackOutcome:
    credentials = _build_credentials(config)

    if fp.attackable_cms:
        logger.info("Phase 4: CMS-aware attack (%s)", fp.cms)
        return attack_cms(
            config.base_url,
            fp,
            results,
            credentials=credentials,
            timeout=config.request_timeout,
            pause=config.pause_between_probes,
            max_attempts=config.max_login_attempts,
        )

    if fp.hosted:
        logger.info("Phase 4: %s is a hosted platform — generic discovery only", fp.cms)
    else:
        logger.info("Phase 4: generic discovery + credential spray (no CMS)")

    return attack_generic(
        config.base_url,
        results,
        sensitive_paths=_load_payload_lines(PAYLOAD_HTTP_PATHS),
        injections=_load_payload_lines(PAYLOAD_HTTP_INJECTIONS),
        credentials=credentials,
        timeout=config.request_timeout,
        pause=config.pause_between_probes,
        max_attempts=config.max_login_attempts,
    )


def run(config: HttpScanConfig, reports_dir: Path) -> HttpScanReport:
    report = HttpScanReport(target=config.base_url)

    results = make_results_dir(reports_dir, prefix="http")
    logger.info("Artefacts directory: %s", results.path)

    home = http_request(config.base_url, "/", timeout=5, capture_body=True)
    if not home.ok:
        logger.error("HTTP honeypot unreachable: %s", home.error)
        report.exit_code = 2
        return report
    logger.info("HTTP target reachable (status %s)", home.status)

    if config.skip_nikto:
        report.skipped_phases.append("nikto")
        logger.warning("Phase 1 skipped (--skip-nikto)")
    else:
        report.nikto_findings = _phase_nikto(config, results)

    if config.skip_dirsearch:
        report.skipped_phases.append("dirsearch")
        logger.warning("Phase 2 skipped (--skip-dirsearch)")
    else:
        _phase_dirsearch(config, results)

    fp = _phase_fingerprint(config, results, home)
    report.cms = fp.cms
    report.cms_version = fp.cms_version
    report.cms_confidence = fp.cms_confidence
    report.server = fp.server
    report.technologies = fp.technologies

    if config.skip_login:
        report.skipped_phases.append("attack")
        logger.warning("Phase 4 skipped (--skip-login)")
    else:
        outcome = _phase_attack(config, results, fp)
        report.login_attempts = outcome.login_attempts
        report.credentials_found = outcome.credentials_found
        report.sensitive_paths = outcome.sensitive_paths
        report.findings = outcome.findings

    _write_findings(results, report)
    _write_summary(results, config, report)
    return report


def _write_findings(results: ResultsDir, report: HttpScanReport) -> None:
    if not report.findings:
        results.file("findings.txt").write_text("(no findings)\n", encoding="utf-8")
        return

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(report.findings, key=lambda f: order.get(f.severity, 5))
    body = "\n".join(finding.line() for finding in ranked)
    results.file("findings.txt").write_text(body + "\n", encoding="utf-8")


def _write_summary(
    results: ResultsDir,
    config: HttpScanConfig,
    report: HttpScanReport,
) -> None:
    summary = results.file("summary.txt")
    lines = [
        f"target: {report.target}",
        f"target_port: {config.target_port}",
        f"cms: {report.cms or 'unknown'} ({report.cms_confidence}%)",
        f"cms_version: {report.cms_version or 'unknown'}",
        f"server: {report.server or 'unknown'}",
        f"technologies: {', '.join(report.technologies) or '-'}",
        f"nikto_findings: {report.nikto_findings}",
        f"login_attempts: {report.login_attempts}",
        f"credentials_found: {report.credentials_found}",
        f"sensitive_paths: {report.sensitive_paths}",
        f"total_findings: {len(report.findings)}",
        f"skipped_phases: {','.join(report.skipped_phases) or 'none'}",
        f"exit_code: {report.exit_code}",
    ]

    summary.write_text("\n".join(lines), encoding="utf-8")
