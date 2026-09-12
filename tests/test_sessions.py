from datetime import datetime, timedelta, timezone

from access_log_triage.analysis import split_sessions
from access_log_triage.models import LogEntry


def entry(minutes: int) -> LogEntry:
    timestamp = datetime(2026, 9, 10, 13, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)
    return LogEntry(
        ip="192.0.2.1", timestamp=timestamp, timezone="+0000", method="GET",
        request_target="/", path="/", query_string="", protocol="HTTP/1.1",
        status=200, response_bytes=10, referer=None, user_agent=None,
        raw_line="synthetic", line_number=minutes + 1,
    )


def test_session_split_after_more_than_30_minutes():
    sessions = split_sessions([entry(65), entry(0), entry(20), entry(60), entry(10)], 30)
    assert [[item.timestamp.minute for item in session.entries] for session in sessions] == [
        [0, 10, 20], [0, 5]
    ]


def test_exactly_30_minutes_stays_in_same_session():
    assert len(split_sessions([entry(0), entry(30)], 30)) == 1


def test_empty_input_and_invalid_gap():
    assert split_sessions([], 30) == []
    try:
        split_sessions([entry(0)], 0)
    except ValueError as error:
        assert "at least 1" in str(error)
    else:
        raise AssertionError("Expected ValueError")
