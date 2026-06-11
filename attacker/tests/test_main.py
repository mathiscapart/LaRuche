"""Unit tests for attacker.main CLI parsing and campaign planning."""

from __future__ import annotations

import argparse
import json
from datetime import datetime

from attacker import main
from attacker import report as report_mod
from attacker.main import (
    _apply_cross_protocol_honeypot,
    _CampaignOutcome,
    _collect_protocol_signals,
    _plan_campaigns,
    _resolve_port,
    _run_campaign,
    build_parser,
)


# --- build_parser ----------------------------------------------------------
def test_parser_ssh_full_wordlist_and_defaults():
    args = build_parser().parse_args(
        ["ssh", "--target", "1.2.3.4", "--full-wordlist", "--default-credentials", "/c"]
    )
    assert args.command == "ssh"
    assert args.target == "1.2.3.4"
    assert args.full_wordlist is True
    assert str(args.default_credentials) == "/c"


def test_parser_ftp_defaults():
    args = build_parser().parse_args(["ftp"])
    assert args.command == "ftp"
    assert args.full_wordlist is False
    assert args.default_credentials is None


def test_parser_all_parallel_flag():
    args = build_parser().parse_args(["all", "--parallel"])
    assert args.parallel is True
    assert build_parser().parse_args(["all"]).parallel is False


# --- _resolve_port ---------------------------------------------------------
def test_resolve_port_uses_explicit():
    assert _resolve_port("h", 2222, (22, 2222)) == 2222


def test_resolve_port_picks_first_reachable(monkeypatch):
    monkeypatch.setattr(main, "is_reachable", lambda h, p: p == 2222)
    assert _resolve_port("h", None, (22, 2222)) == 2222


def test_resolve_port_defaults_to_last_when_none_reachable(monkeypatch):
    monkeypatch.setattr(main, "is_reachable", lambda h, p: False)
    assert _resolve_port("h", None, (22, 2222)) == 2222


# --- _plan_campaigns -------------------------------------------------------
def _all_args(**overrides):
    base = {
        "skip_http": False, "skip_ftp": False, "skip_ssh": False,
        "http_port": None, "ftp_port": None, "ssh_port": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_plan_campaigns_from_discovery():
    plan = _plan_campaigns(_all_args(), {"ssh": [22], "http": [80, 8080]})
    assert ("ssh", 22) in plan
    assert ("http", 80) in plan
    assert ("http", 8080) in plan


def test_plan_campaigns_respects_skip():
    plan = _plan_campaigns(_all_args(skip_ssh=True), {"ssh": [22]})
    assert plan == []


def test_plan_campaigns_forced_port_overrides_discovery():
    plan = _plan_campaigns(_all_args(ftp_port=2121), {})
    assert plan == [("ftp", 2121)]


def test_plan_campaigns_empty_discovery():
    assert _plan_campaigns(_all_args(), {}) == []


# --- _run_campaign ---------------------------------------------------------
def test_run_campaign_records_exit_code(monkeypatch, tmp_path):
    monkeypatch.setitem(
        main._CAMPAIGNS, "ssh", (lambda t, p, d: 7, "skip_ssh", "ssh_port")
    )
    outcome = _run_campaign("ssh", 22, "host", tmp_path)
    assert isinstance(outcome, _CampaignOutcome)
    assert outcome.name == "ssh:22"
    assert outcome.exit_code == 7
    assert outcome.skipped is False


# --- cross-protocol honeypot aggregation (the "all" report) ----------------
def _write_service_report(consolidated, sub, protocol, score, suspected):
    sub_dir = consolidated / sub
    sub_dir.mkdir(parents=True, exist_ok=True)
    (sub_dir / "report.json").write_text(
        json.dumps(
            {
                "protocol": protocol,
                "honeypot": {
                    "suspected": suspected,
                    "score": score,
                    "signals": [{"indicator": "x", "detail": "y", "weight": score}],
                },
            }
        ),
        encoding="utf-8",
    )


def test_collect_protocol_signals_reads_subdirs(tmp_path):
    _write_service_report(tmp_path, "ssh-1", "ssh", 60, True)
    _write_service_report(tmp_path, "ftp-1", "ftp", 5, False)
    signals = _collect_protocol_signals(tmp_path)
    assert {s.protocol for s in signals} == {"ssh", "ftp"}
    assert {s.score for s in signals} == {60, 5}


def test_apply_cross_protocol_flags_broad_cooperation(tmp_path):
    _write_service_report(tmp_path, "ssh-1", "ssh", 55, True)
    _write_service_report(tmp_path, "ftp-1", "ftp", 55, True)
    rich = report_mod.Report(
        title="t", target="h", protocol="all", host="h", port=0,
        started_at=datetime.now(),
    )
    _apply_cross_protocol_honeypot(rich, tmp_path)
    assert rich.honeypot is not None
    assert rich.honeypot.suspected is True
    assert rich.honeypot.score == 80  # 55 + 25 breadth bonus
    assert any("near-conclusive" in note for note in rich.notes)


def test_apply_cross_protocol_noop_without_reports(tmp_path):
    rich = report_mod.Report(
        title="t", target="h", protocol="all", host="h", port=0,
        started_at=datetime.now(),
    )
    _apply_cross_protocol_honeypot(rich, tmp_path)
    assert rich.honeypot is None
