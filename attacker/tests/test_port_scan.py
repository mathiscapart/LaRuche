"""Unit tests for attacker.recon.port_scan (nmap parsing, no real nmap)."""

from __future__ import annotations

import pytest

from attacker.recon import port_scan
from attacker.recon.port_scan import (
    DiscoveredService,
    NmapError,
    _parse_greppable,
    classify,
    discover_services,
)


# --- classify --------------------------------------------------------------
def test_classify_maps_known_services():
    assert classify("ssh") == "ssh"
    assert classify(" HTTP ") == "http"
    assert classify("https") == "http"
    assert classify("ftp-data") == "ftp"


def test_classify_unknown_is_none():
    assert classify("telnet") is None


def test_discovered_service_attack_property():
    assert DiscoveredService(22, "ssh").attack == "ssh"
    assert DiscoveredService(23, "telnet").attack is None


# --- _parse_greppable ------------------------------------------------------
def test_parse_greppable_extracts_open_ports():
    stdout = (
        "# Nmap\n"
        "Host: 10.0.0.1 ()  Ports: 22/open/tcp//ssh//OpenSSH 8.2//, "
        "80/open/tcp//http//nginx//, 443/closed/tcp//https//   "
        "Ignored State: closed (997)\n"
    )
    services = _parse_greppable(stdout)
    by_port = {s.port: s for s in services}
    assert set(by_port) == {22, 80}
    assert by_port[22].service == "ssh"
    assert by_port[22].version == "OpenSSH 8.2"
    assert by_port[80].service == "nginx" or by_port[80].service == "http"


def test_parse_greppable_deduplicates_ports():
    stdout = (
        "Host: x ()  Ports: 22/open/tcp//ssh//x//\n"
        "Host: x ()  Ports: 22/open/tcp//ssh//x//\n"
    )
    assert len(_parse_greppable(stdout)) == 1


def test_parse_greppable_ignores_lines_without_ports():
    assert _parse_greppable("Host: x () Status: Up\n") == []


# --- discover_services error handling --------------------------------------
class _FakeResult:
    def __init__(self, return_code, stdout, stderr, timed_out):
        self.return_code = return_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.duration_s = 0.1


def test_discover_services_missing_binary(monkeypatch):
    monkeypatch.setattr(
        port_scan, "run_command", lambda *a, **k: _FakeResult(127, "", "", False)
    )
    with pytest.raises(NmapError, match="not found"):
        discover_services("host")


def test_discover_services_timeout(monkeypatch):
    monkeypatch.setattr(
        port_scan, "run_command", lambda *a, **k: _FakeResult(124, "", "", True)
    )
    with pytest.raises(NmapError, match="timed out"):
        discover_services("host", timeout=5)


def test_discover_services_nonzero_exit(monkeypatch):
    monkeypatch.setattr(
        port_scan, "run_command", lambda *a, **k: _FakeResult(1, "", "boom", False)
    )
    with pytest.raises(NmapError, match="rc=1"):
        discover_services("host")


def test_discover_services_parses_success(monkeypatch):
    stdout = "Host: h ()  Ports: 2222/open/tcp//ssh//x//\n"
    monkeypatch.setattr(
        port_scan, "run_command", lambda *a, **k: _FakeResult(0, stdout, "", False)
    )
    services = discover_services("host")
    assert services[0].port == 2222
    assert services[0].attack == "ssh"
