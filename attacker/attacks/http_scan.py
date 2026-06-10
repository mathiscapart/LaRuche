from __future__ import annotations

import logging
import shutil
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from attacker.attacks.common import (
    HttpResponse,
    ResultsDir,
    ensure_allowed,
    http_request,
    make_results_dir,
    run_command,
)
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
    skip_nikto: bool = False
    skip_dirsearch: bool = False
    bypass_allowlist: bool = False
    dirsearch_wordlist: Path | None = None

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
    nikto_findings: int = 0
    probes_sent: int = 0
    skipped_phases: list[str] = field(default_factory=list)
    exit_code: int = 0


def _phase_nikto(config: HttpScanConfig, results: ResultsDir) -> int:
    output_csv = results.file("nikto.csv")
    output_txt = results.file("nikto.txt")
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
    output_log = results.file("dirsearch.txt")
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
        "--format",
        "json",
    ]
    logger.info("Phase 2: dirsearch (wordlist=%s)", wordlist)
    result = run_command(cmd, timeout=config.dirsearch_timeout, log_to=output_log)
    logger.info(
        "dirsearch completed in %.1fs (rc=%d)", result.duration_s, result.return_code
    )
    return True


def _phase_probes(config: HttpScanConfig, results: ResultsDir) -> list[HttpResponse]:
    paths = load_lines(PAYLOAD_HTTP_PATHS)
    injections = load_lines(PAYLOAD_HTTP_INJECTIONS)
    logger.info(
        "Phase 3: targeted probes (%d paths + %d injections)",
        len(paths),
        len(injections),
    )

    probes: list[HttpResponse] = []
    summary_lines: list[str] = []

    for path in paths:
        encoded = _ensure_path_encoded(path)
        response = http_request(
            config.base_url,
            encoded,
            timeout=config.request_timeout,
        )
        probes.append(response)
        summary_lines.append(_format_probe_line(response))
        logger.debug("GET %s -> %s", encoded, response.status or response.error)
        time.sleep(config.pause_between_probes)

    for injection in injections:
        encoded = _ensure_path_encoded(injection)
        response = http_request(
            config.base_url,
            encoded,
            timeout=config.request_timeout,
        )
        probes.append(response)
        summary_lines.append(_format_probe_line(response))
        logger.debug("GET %s -> %s", encoded, response.status or response.error)
        time.sleep(config.pause_between_probes)

    # POST examples to exercise authenticated routes that the honeypot logs.
    form_body = urllib.parse.urlencode(
        {
            "log": "admin",
            "pwd": "password123",
            "wp-submit": "Log In",
        }
    ).encode()
    response = http_request(
        config.base_url,
        "/wp-login.php",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=form_body,
        timeout=config.request_timeout,
    )
    probes.append(response)
    summary_lines.append(_format_probe_line(response))

    response = http_request(
        config.base_url,
        "/admin",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=b'{"username":"admin","password":"admin123"}',
        timeout=config.request_timeout,
    )
    probes.append(response)
    summary_lines.append(_format_probe_line(response))

    results.file("probes.txt").write_text("\n".join(summary_lines), encoding="utf-8")
    logger.info("Sent %d probes", len(probes))
    return probes


def _ensure_path_encoded(raw: str) -> str:
    if not raw.startswith("/"):
        raw = "/" + raw

    return urllib.parse.quote(raw, safe="/?=&-._~")


def _format_probe_line(response: HttpResponse) -> str:
    status = (
        str(response.status)
        if response.status is not None
        else f"ERR({response.error})"
    )

    return f"{response.method:<4} {response.path:<60} {status}"


def run(config: HttpScanConfig, reports_dir: Path) -> HttpScanReport:
    report = HttpScanReport(target=config.base_url)

    if not ensure_allowed(config.target_host, bypass=config.bypass_allowlist):
        report.exit_code = 2
        return report

    results = make_results_dir(reports_dir, prefix="http")
    logger.info("Artefacts directory: %s", results.path)

    probe = http_request(config.base_url, "/", timeout=5)
    if not probe.ok:
        logger.error("HTTP honeypot unreachable: %s", probe.error)
        report.exit_code = 2
        return report

    logger.info("HTTP honeypot reachable (status %s)", probe.status)
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

    probes = _phase_probes(config, results)
    report.probes_sent = len(probes)

    _write_summary(results, config, report)
    return report


def _write_summary(
    results: ResultsDir,
    config: HttpScanConfig,
    report: HttpScanReport,
) -> None:
    summary = results.file("summary.txt")
    lines = [
        f"target: {report.target}",
        f"nikto_findings: {report.nikto_findings}",
        f"probes_sent: {report.probes_sent}",
        f"skipped_phases: {','.join(report.skipped_phases) or 'none'}",
        f"exit_code: {report.exit_code}",
        f"target_port: {config.target_port}",
    ]

    summary.write_text("\n".join(lines), encoding="utf-8")
