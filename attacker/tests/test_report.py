"""Unit tests for the report builder (Markdown + JSON rendering)."""

from __future__ import annotations

import json
from datetime import datetime

from attacker import report as r


def _report(**overrides) -> r.Report:
    base = {
        "title": "SSH Brute-Force Assessment",
        "target": "ssh://10.0.0.1:2222",
        "protocol": "ssh",
        "host": "10.0.0.1",
        "port": 2222,
        "started_at": datetime(2026, 6, 11, 10, 15, 0),
    }
    base.update(overrides)
    return r.Report(**base)


# --- risk rating / status --------------------------------------------------
def test_risk_rating_critical_when_credentials_found():
    rep = _report(credentials=[r.ReportCredential("root", "root", "SSH")])
    assert rep.risk_rating == "Critical"
    assert "compromised" in rep.status_banner.lower()


def test_risk_rating_follows_highest_severity():
    rep = _report(
        findings=[r.ReportFinding("medium", "x"), r.ReportFinding("low", "y")]
    )
    assert rep.highest_severity == "medium"
    assert rep.risk_rating == "Medium"


def test_risk_rating_informational_when_clean():
    assert _report().risk_rating == "Informational"
    assert "🟢" in _report().status_banner


def test_status_banner_unreachable():
    assert "unreachable" in _report(exit_code=2).status_banner.lower()


def test_status_banner_honeypot():
    rep = _report(honeypot=r.HoneypotAssessment(suspected=True, score=90))
    assert "honeypot" in rep.status_banner.lower()


# --- markdown rendering ----------------------------------------------------
def test_markdown_contains_core_sections():
    rep = _report(
        credentials=[r.ReportCredential("root", "calvin", "SSH")],
        findings=[r.ReportFinding("critical", "Valid SSH credentials accepted", "x")],
        honeypot=r.HoneypotAssessment(
            suspected=True, score=90, signals=(("ssh-bruteforce", "defaults", 90),)
        ),
        phases=[r.ReportPhase("Brute-force (Hydra)", "completed", "2 creds")],
        metrics={"Port": 2222},
    )
    md = rep.to_markdown()
    assert "# SSH Brute-Force Assessment" in md
    assert "## Executive summary" in md
    assert "## Honeypot assessment" in md
    assert "## Compromised credentials" in md
    assert "| `root` | `calvin` | SSH |" in md
    assert "## Findings" in md
    assert "## Phases" in md
    assert "Authorised testing only" in md


def test_markdown_findings_sorted_by_severity():
    rep = _report(
        findings=[
            r.ReportFinding("low", "low-finding"),
            r.ReportFinding("critical", "crit-finding"),
        ]
    )
    md = rep.to_markdown()
    assert md.index("crit-finding") < md.index("low-finding")


def test_markdown_no_findings_placeholder():
    assert "_No findings._" in _report().to_markdown()


# --- json rendering --------------------------------------------------------
def test_to_json_roundtrips_and_has_expected_keys():
    rep = _report(
        credentials=[r.ReportCredential("a", "b", "SSH")],
        honeypot=r.HoneypotAssessment(suspected=False, score=10),
    )
    data = json.loads(json.dumps(rep.to_json()))
    assert data["target"] == "ssh://10.0.0.1:2222"
    assert data["risk_rating"] == "Critical"
    assert data["credentials"][0] == {
        "username": "a",
        "password": "b",
        "service": "SSH",
        "note": "",
    }
    assert data["honeypot"]["score"] == 10


# --- write_report ----------------------------------------------------------
def test_write_report_emits_md_and_json_and_indexes_artefacts(tmp_path):
    (tmp_path / "hydra.log").write_text("x", encoding="utf-8")
    rep = _report()
    path = r.write_report(tmp_path, rep)
    assert path == tmp_path / "report.md"
    assert (tmp_path / "report.md").is_file()
    assert (tmp_path / "report.json").is_file()
    # The pre-existing artefact is indexed; report files are not.
    assert "hydra.log" in rep.artefacts
    assert "report.md" not in rep.artefacts


def test_honeypot_assessment_from_verdict():
    from attacker.attacks.honeypot import HoneypotVerdict

    verdict = HoneypotVerdict(target="ssh://x")
    verdict.add("ssh-banner", "names cowrie", 90)
    assessment = r.honeypot_assessment_from_verdict(verdict)
    assert assessment.suspected is True
    assert assessment.score == 90
    assert assessment.signals == (("ssh-banner", "names cowrie", 90),)
