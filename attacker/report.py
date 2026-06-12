"""Professional report generation for attacker campaigns.

Every campaign builds a structured :class:`Report` and renders it to two files
in the run's artefacts directory:

* ``report.md``   — a polished, human-readable Markdown report (renders cleanly
  on GitHub / any Markdown viewer): executive summary, risk rating, honeypot
  assessment, findings table, compromised credentials, phase breakdown and an
  artefact index.
* ``report.json`` — the same data, machine-readable, so the analyzer or CI can
  consume results without scraping text.

The goal is a real assessment deliverable, not a flat ``key: value`` dump.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from attacker import __version__

# Severity model (shared with web_attacks.Finding strings).
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_SEVERITY_LABEL: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}


@dataclass(frozen=True)
class ReportFinding:
    severity: str  # critical | high | medium | low | info
    title: str
    detail: str = ""


@dataclass(frozen=True)
class ReportCredential:
    username: str
    password: str
    service: str
    note: str = ""


@dataclass(frozen=True)
class ReportPhase:
    name: str
    status: str  # completed | skipped | failed
    summary: str = ""


@dataclass(frozen=True)
class HoneypotAssessment:
    suspected: bool
    score: int
    # (indicator, detail, weight)
    signals: tuple[tuple[str, str, int], ...] = ()


@dataclass
class Report:
    title: str
    target: str
    protocol: str
    host: str
    port: int
    started_at: datetime
    duration_s: float = 0.0
    exit_code: int = 0
    # Ordered key/value metrics shown in the summary table.
    metrics: dict[str, object] = field(default_factory=dict)
    phases: list[ReportPhase] = field(default_factory=list)
    findings: list[ReportFinding] = field(default_factory=list)
    credentials: list[ReportCredential] = field(default_factory=list)
    honeypot: HoneypotAssessment | None = None
    artefacts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    # --- derived ----------------------------------------------------------
    @property
    def highest_severity(self) -> str | None:
        if not self.findings:
            return None
        return min(
            self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5)
        ).severity

    @property
    def risk_rating(self) -> str:
        """Overall risk: driven by the worst finding, escalated if creds fell."""
        if self.credentials:
            return "Critical"
        top = self.highest_severity
        if top is None:
            return "Informational"
        return _SEVERITY_LABEL.get(top, "Informational")

    @property
    def status_banner(self) -> str:
        if self.exit_code == 2:
            return "🚫 Target unreachable"
        if self.credentials:
            return "🔴 Credentials compromised"
        if self.honeypot and self.honeypot.suspected:
            return "🟠 Honeypot suspected"
        if self.findings:
            return "🟡 Findings reported"
        return "🟢 No weak credentials or findings"

    # --- rendering --------------------------------------------------------
    def _executive_summary(self) -> str:
        bits: list[str] = []
        if self.exit_code == 2:
            return (
                f"The target `{self.target}` was **unreachable**; no assessment "
                "could be performed."
            )

        if self.credentials:
            bits.append(
                f"The brute-force phase **compromised {len(self.credentials)} "
                f"credential(s)** on `{self.target}`."
            )
        else:
            bits.append(f"No valid credentials were recovered against `{self.target}`.")

        crit_high = sum(1 for f in self.findings if f.severity in ("critical", "high"))
        if crit_high:
            bits.append(
                f"{crit_high} high-severity finding(s) were raised "
                f"(overall risk rating: **{self.risk_rating}**)."
            )

        if self.honeypot and self.honeypot.suspected:
            bits.append(
                f"⚠️ The target **looks like a honeypot / decoy** "
                f"(confidence {self.honeypot.score}%); treat the results above "
                "as instrumented and logged."
            )

        return " ".join(bits)

    def to_markdown(self) -> str:
        lines: list[str] = []
        lines.append(f"# {self.title}")
        lines.append("")
        started = self.started_at.strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"- **Target:** `{self.target}`")
        lines.append(f"- **Date:** {started}")
        lines.append(f"- **Tool:** attacker v{__version__}")
        lines.append(f"- **Duration:** {self.duration_s:.1f}s")
        lines.append(f"- **Status:** {self.status_banner}")
        lines.append(f"- **Risk rating:** {self.risk_rating}")
        lines.append("")
        lines.append("## Executive summary")
        lines.append("")
        lines.append(self._executive_summary())
        lines.append("")

        # Key metrics table.
        if self.metrics:
            lines.append("## Key metrics")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            for key, value in self.metrics.items():
                lines.append(f"| {key} | {value} |")
            lines.append("")

        # Honeypot assessment.
        if self.honeypot is not None:
            lines.append("## Honeypot assessment")
            lines.append("")
            if self.honeypot.suspected:
                lines.append(
                    f"> ⚠️ **Honeypot suspected** — confidence "
                    f"**{self.honeypot.score}%**."
                )
            else:
                lines.append(
                    f"> ✅ No strong honeypot indicators "
                    f"(score {self.honeypot.score}%)."
                )
            lines.append("")
            if self.honeypot.signals:
                lines.append("| Indicator | Evidence | Weight |")
                lines.append("|-----------|----------|--------|")
                for indicator, detail, weight in self.honeypot.signals:
                    lines.append(f"| `{indicator}` | {detail} | +{weight} |")
                lines.append("")

        # Compromised credentials.
        if self.credentials:
            lines.append("## Compromised credentials")
            lines.append("")
            lines.append("| Username | Password | Service | Note |")
            lines.append("|----------|----------|---------|------|")
            for cred in self.credentials:
                lines.append(
                    f"| `{cred.username}` | `{cred.password}` | "
                    f"{cred.service} | {cred.note or '-'} |"
                )
            lines.append("")

        # Findings table.
        lines.append("## Findings")
        lines.append("")
        if self.findings:
            ranked = sorted(
                self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5)
            )
            lines.append("| # | Severity | Finding | Detail |")
            lines.append("|---|----------|---------|--------|")
            for idx, finding in enumerate(ranked, start=1):
                sev = _SEVERITY_LABEL.get(finding.severity, finding.severity)
                lines.append(
                    f"| {idx} | {sev} | {finding.title} | {finding.detail or '-'} |"
                )
        else:
            lines.append("_No findings._")
        lines.append("")

        # Phase breakdown.
        if self.phases:
            lines.append("## Phases")
            lines.append("")
            lines.append("| Phase | Status | Summary |")
            lines.append("|-------|--------|---------|")
            for phase in self.phases:
                icon = {
                    "completed": "✅",
                    "skipped": "⏭️",
                    "failed": "❌",
                }.get(phase.status, "")
                lines.append(
                    f"| {phase.name} | {icon} {phase.status} | {phase.summary or '-'} |"
                )
            lines.append("")

        # Artefacts.
        if self.artefacts:
            lines.append("## Artefacts")
            lines.append("")
            for name in sorted(self.artefacts):
                lines.append(f"- `{name}`")
            lines.append("")

        if self.notes:
            lines.append("## Notes")
            lines.append("")
            for note in self.notes:
                lines.append(f"- {note}")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(
            "_Generated by attacker — honeypot validation toolkit (M1SPRO B10). "
            "Authorised testing only._"
        )
        return "\n".join(lines) + "\n"

    def to_json(self) -> dict:
        return {
            "title": self.title,
            "target": self.target,
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "started_at": self.started_at.isoformat(),
            "duration_s": round(self.duration_s, 2),
            "exit_code": self.exit_code,
            "status": self.status_banner,
            "risk_rating": self.risk_rating,
            "metrics": self.metrics,
            "honeypot": (
                None
                if self.honeypot is None
                else {
                    "suspected": self.honeypot.suspected,
                    "score": self.honeypot.score,
                    "signals": [
                        {"indicator": i, "detail": d, "weight": w}
                        for i, d, w in self.honeypot.signals
                    ],
                }
            ),
            "credentials": [
                {
                    "username": c.username,
                    "password": c.password,
                    "service": c.service,
                    "note": c.note,
                }
                for c in self.credentials
            ],
            "findings": [
                {"severity": f.severity, "title": f.title, "detail": f.detail}
                for f in self.findings
            ],
            "phases": [
                {"name": p.name, "status": p.status, "summary": p.summary}
                for p in self.phases
            ],
            "artefacts": sorted(self.artefacts),
            "notes": self.notes,
        }


def honeypot_assessment_from_verdict(verdict) -> HoneypotAssessment:
    """Build a :class:`HoneypotAssessment` from a honeypot ``HoneypotVerdict``."""
    return HoneypotAssessment(
        suspected=verdict.is_suspected,
        score=verdict.score,
        signals=tuple((s.indicator, s.detail, s.weight) for s in verdict.signals),
    )


def collect_artefacts(directory: Path) -> list[str]:
    """List artefact file names already written in the run directory."""
    if not directory.is_dir():
        return []
    return [p.name for p in directory.iterdir() if p.is_file()]


def write_report(directory: Path, report: Report) -> Path:
    """Render ``report`` to ``report.md`` and ``report.json`` in ``directory``.

    Artefacts already present in the directory are indexed automatically (the
    report files themselves are excluded).
    """
    directory.mkdir(parents=True, exist_ok=True)
    existing = {"report.md", "report.json"}
    report.artefacts = [
        name for name in collect_artefacts(directory) if name not in existing
    ]

    md_path = directory / "report.md"
    md_path.write_text(report.to_markdown(), encoding="utf-8")
    (directory / "report.json").write_text(
        json.dumps(report.to_json(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return md_path
