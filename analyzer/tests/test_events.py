"""Tests du lecteur d'événements JSONL (analyzer.events)."""

from analyzer.events import group_by_session, iter_events, load_log_dir


def test_iter_events_skips_invalid_lines(tmp_path) -> None:
    f = tmp_path / "http.jsonl"
    f.write_text(
        '{"id":"1","src_ip":"1.2.3.4","event_type":"request"}\n'
        "\n"
        "pas du json\n"
        '{"id":"2","src_ip":"1.2.3.4","event_type":"credential_attempt"}\n',
        encoding="utf-8",
    )
    events = list(iter_events([f]))
    assert len(events) == 2
    assert events[0]["id"] == "1"


def test_iter_events_ignores_missing_file(tmp_path) -> None:
    assert list(iter_events([tmp_path / "nope.jsonl"])) == []


def test_load_log_dir_reads_all_jsonl(tmp_path) -> None:
    (tmp_path / "ssh.jsonl").write_text('{"id":"a","src_ip":"1.1.1.1"}\n', encoding="utf-8")
    (tmp_path / "http.jsonl").write_text('{"id":"b","src_ip":"2.2.2.2"}\n', encoding="utf-8")
    assert len(load_log_dir(tmp_path)) == 2


def test_group_by_session_prefers_session_id() -> None:
    events = [
        {"session_id": "s1", "src_ip": "1.1.1.1"},
        {"session_id": "s1", "src_ip": "1.1.1.1"},
        {"src_ip": "2.2.2.2"},
    ]
    sessions = group_by_session(events)
    assert len(sessions["s1"]) == 2
    assert len(sessions["2.2.2.2"]) == 1
