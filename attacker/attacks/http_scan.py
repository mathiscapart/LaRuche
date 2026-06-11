"""Professional HTTP scan pipeline (M1SPRO brick B10).

The phases run in a logical order — identify first, discover next, attack last —
and each one feeds the next instead of running in isolation:

  1. Fingerprint   — identify the CMS / server / stack (web_fingerprint). Cheap
                     (it reuses the homepage already fetched) and it decides how
                     every later phase behaves.
  2. Nikto         — broad vulnerability scan (optional, external tool); its
                     findings are merged into the unified findings report.
  3. dirsearch     — content discovery (optional, external tool); the endpoints
                     it uncovers are parsed and handed to phase 4.
  4. Targeted attack — CMS-aware login + recon when a CMS is detected
                     (web_attacks.attack_cms), otherwise a generic discovery +
                     credential spray (web_attacks.attack_generic). Both are fed
                     the fingerprint *and* the paths discovered in phase 3.

So the fingerprint adapts the attack to the target and the discovery phase
widens its attack surface, instead of firing the same payloads everywhere.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import shutil
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from attacker.attacks.common import (
    HttpResponse,
    ResultsDir,
    http_request,
    make_results_dir,
    resolve_password_wordlist,
    resolve_username_wordlist,
    run_command,
)
from attacker.attacks.honeypot import analyze_logins, detect_http, warn_if_suspected
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
    discovered_paths: int = 0
    login_attempts: int = 0
    credentials_found: int = 0
    sensitive_paths: int = 0
    honeypot_suspected: bool = False
    findings: list[Finding] = field(default_factory=list)
    skipped_phases: list[str] = field(default_factory=list)
    exit_code: int = 0


def _parse_nikto_csv(output_csv: Path, target_host: str) -> list[Finding]:
    """Turn nikto's CSV rows into findings so they join the unified report.

    Columns are: host, ip, port, osvdb-id, method, uri, description.
    """
    if not output_csv.exists():
        return []

    text = output_csv.read_text(encoding="utf-8", errors="replace")
    findings: list[Finding] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 7 or row[0] != target_host:
            continue
        uri, description = row[5], row[6].strip()
        if not description:
            continue
        findings.append(Finding("low", f"Nikto: {description[:120]}", uri))

    return findings


def _phase_nikto(config: HttpScanConfig, results: ResultsDir) -> list[Finding]:
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
    logger.info("Phase 2: Nikto against %s", config.base_url)

    result = run_command(cmd, timeout=config.nikto_timeout + 10, log_to=output_txt)
    if result.return_code == 127:
        logger.error("nikto binary not found — skipping phase 2")
        return []

    findings = _parse_nikto_csv(output_csv, config.target_host)
    logger.info(
        "Nikto completed in %.1fs (%d findings)", result.duration_s, len(findings)
    )

    return findings


def _locate_dirsearch() -> list[str] | None:
    if shutil.which("dirsearch"):
        return ["dirsearch"]

    for alt in ("/usr/share/dirsearch/dirsearch.py", "/opt/dirsearch/dirsearch.py"):
        if Path(alt).is_file():
            return ["python3", alt]

    return None


# Statuses worth handing to the attack phase: live content or gated endpoints.
_DISCOVERY_STATUSES = {200, 201, 204, 301, 302, 307, 401, 403, 405}
_MAX_DISCOVERED_PATHS = 50


def _parse_dirsearch_json(output_json: Path) -> list[str]:
    """Extract interesting endpoint *paths* from dirsearch's JSON report."""
    if not output_json.is_file():
        return []

    try:
        data = json.loads(output_json.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, OSError):
        return []

    results = data.get("results", []) if isinstance(data, dict) else []
    paths: list[str] = []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        if entry.get("status") not in _DISCOVERY_STATUSES:
            continue

        raw = entry.get("path") or entry.get("url") or ""
        if raw.startswith(("http://", "https://")):
            raw = urllib.parse.urlsplit(raw).path
        path = raw if raw.startswith("/") else "/" + raw
        if path != "/" and path not in paths:
            paths.append(path)
        if len(paths) >= _MAX_DISCOVERED_PATHS:
            break

    return paths


def _phase_dirsearch(config: HttpScanConfig, results: ResultsDir) -> list[str]:
    command_prefix = _locate_dirsearch()
    if command_prefix is None:
        logger.warning("dirsearch not found — phase 3 skipped")
        return []

    wordlist = config.dirsearch_wordlist or ensure_dirsearch_wordlist()
    if wordlist is None:
        logger.warning("No dirsearch wordlist available — phase 3 skipped")
        return []

    output_json = results.file("dirsearch.json")
    output_log = results.file("dirsearch.log")
    cmd = [
        *command_prefix,
        "-u",
        config.base_url,
        "-w",
        str(wordlist),
        # Append common file extensions so the wordlist's base-names also probe
        # for sensitive files (configs, backups, dumps), not just directories.
        "-e",
        "php,txt,bak,old,zip,sql,conf,json,env",
        "-t",
        str(config.dirsearch_threads),
        "--timeout",
        str(int(config.request_timeout)),
        "-o",
        str(output_json),
        "-O",
        "json",
    ]
    logger.info("Phase 3: dirsearch (wordlist=%s)", wordlist)
    result = run_command(cmd, timeout=config.dirsearch_timeout, log_to=output_log)
    discovered = _parse_dirsearch_json(output_json)
    logger.info(
        "dirsearch completed in %.1fs (rc=%d, %d path(s) discovered)",
        result.duration_s,
        result.return_code,
        len(discovered),
    )
    return discovered


def _phase_fingerprint(
    config: HttpScanConfig,
    results: ResultsDir,
    home: HttpResponse,
) -> Fingerprint:
    logger.info("Phase 1: fingerprinting %s", config.base_url)
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
    discovered_paths: list[str],
) -> AttackOutcome:
    credentials = _build_credentials(config)

    if fp.attackable_cms:
        logger.info(
            "Phase 4: CMS-aware attack (%s, +%d discovered path(s))",
            fp.cms,
            len(discovered_paths),
        )
        return attack_cms(
            config.base_url,
            fp,
            results,
            credentials=credentials,
            extra_paths=discovered_paths,
            timeout=config.request_timeout,
            pause=config.pause_between_probes,
            max_attempts=config.max_login_attempts,
        )

    if fp.hosted:
        logger.info("Phase 4: %s is a hosted platform — generic discovery only", fp.cms)
    else:
        logger.info(
            "Phase 4: generic discovery + credential spray (no CMS, +%d discovered "
            "path(s))",
            len(discovered_paths),
        )

    return attack_generic(
        config.base_url,
        results,
        sensitive_paths=_load_payload_lines(PAYLOAD_HTTP_PATHS),
        injections=_load_payload_lines(PAYLOAD_HTTP_INJECTIONS),
        credentials=credentials,
        extra_paths=discovered_paths,
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
        logger.error("HTTP target unreachable: %s", home.error)
        report.exit_code = 2
        return report
    logger.info("HTTP target reachable (status %s)", home.status)

    # Pre-attack passive/active honeypot check (signatures + catch-all + auth
    # realm probe). The verdict is finalised after phase 4 with the full set of
    # cracked credentials, keeping detection coherent with the attack.
    verdict = detect_http(config.base_url, home, timeout=config.request_timeout)

    # Phase 1: fingerprint first — it is cheap and drives every later phase.
    fp = _phase_fingerprint(config, results, home)
    report.cms = fp.cms
    report.cms_version = fp.cms_version
    report.cms_confidence = fp.cms_confidence
    report.server = fp.server
    report.technologies = fp.technologies

    # Phase 2: broad vulnerability scan; findings join the unified report.
    if config.skip_nikto:
        report.skipped_phases.append("nikto")
        logger.warning("Phase 2 skipped (--skip-nikto)")
    else:
        nikto_findings = _phase_nikto(config, results)
        report.nikto_findings = len(nikto_findings)
        report.findings.extend(nikto_findings)

    # Phase 3: content discovery; the endpoints found feed the attack phase.
    discovered_paths: list[str] = []
    if config.skip_dirsearch:
        report.skipped_phases.append("dirsearch")
        logger.warning("Phase 3 skipped (--skip-dirsearch)")
    else:
        discovered_paths = _phase_dirsearch(config, results)
        report.discovered_paths = len(discovered_paths)

    # Phase 4: targeted attack, informed by the fingerprint and the discovery.
    if config.skip_login:
        report.skipped_phases.append("attack")
        logger.warning("Phase 4 skipped (--skip-login)")
    else:
        outcome = _phase_attack(config, results, fp, discovered_paths)
        report.login_attempts = outcome.login_attempts
        report.credentials_found = outcome.credentials_found
        report.sensitive_paths = outcome.sensitive_paths
        report.findings.extend(outcome.findings)
        # Coherence: feed the full credential spray back into the verdict.
        analyze_logins(
            verdict,
            outcome.found_credentials,
            protocol="http",
            indicator="http-bruteforce",
        )

    report.honeypot_suspected = warn_if_suspected(verdict, logger)

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
        f"discovered_paths: {report.discovered_paths}",
        f"login_attempts: {report.login_attempts}",
        f"credentials_found: {report.credentials_found}",
        f"sensitive_paths: {report.sensitive_paths}",
        f"honeypot_suspected: {report.honeypot_suspected}",
        f"total_findings: {len(report.findings)}",
        f"skipped_phases: {','.join(report.skipped_phases) or 'none'}",
        f"exit_code: {report.exit_code}",
    ]

    summary.write_text("\n".join(lines), encoding="utf-8")
