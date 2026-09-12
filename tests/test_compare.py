from datetime import datetime, timedelta, timezone
from pathlib import Path

from access_log_triage.analysis import compare_application_journeys, split_sessions
from access_log_triage.models import LogEntry
from access_log_triage.parser import parse_lines


def entry(sequence: int, path: str, method: str = "GET", target: str | None = None) -> LogEntry:
    timestamp = datetime(2026, 9, 10, 13, 0, tzinfo=timezone.utc) + timedelta(seconds=sequence)
    request_target = target or path
    query = request_target.partition("?")[2]
    return LogEntry(
        ip="192.0.2.1", timestamp=timestamp, timezone="+0000", method=method,
        request_target=request_target, path=path, query_string=query,
        protocol="HTTP/1.1", status=200, response_bytes=10, referer=None,
        user_agent="UA", raw_line="synthetic", line_number=sequence,
    )


def test_same_prefix_and_first_divergence():
    left = [entry(i, path) for i, path in enumerate(
        ["/", "/portal", "/request", "/contact", "/help"], 1
    )]
    right = [entry(i, path) for i, path in enumerate(
        ["/", "/portal", "/request", "/contact", "/details"], 1
    )]

    comparison = compare_application_journeys(left, right)

    assert comparison.common_prefix_length == 4
    assert comparison.rows[4].left.path == "/help"
    assert comparison.rows[4].right.path == "/details"
    assert comparison.rows[4].different


def test_different_lengths_marks_remaining_rows_only_in_session_two():
    left = [entry(1, "/"), entry(2, "/request")]
    right = [entry(1, "/"), entry(2, "/request"), entry(3, "/details"), entry(4, "/payment")]

    comparison = compare_application_journeys(left, right)

    assert comparison.common_prefix_length == 2
    assert [row.right.path for row in comparison.rows[2:]] == ["/details", "/payment"]
    assert all(row.left is None for row in comparison.rows[2:])
    assert all(row.only_in_session == 2 for row in comparison.rows[2:])


def test_method_is_part_of_comparison_key():
    comparison = compare_application_journeys(
        [entry(1, "/request", "GET")],
        [entry(1, "/request", "POST")],
    )
    assert comparison.common_prefix_length == 0
    assert comparison.rows[0].different


def test_static_requests_are_excluded():
    comparison = compare_application_journeys(
        [entry(1, "/"), entry(2, "/assets/app.js"), entry(3, "/request")],
        [entry(1, "/"), entry(2, "/request")],
    )
    assert [item.path for item in comparison.left] == ["/", "/request"]
    assert comparison.common_prefix_length == 2


def test_query_strings_do_not_affect_path_comparison():
    comparison = compare_application_journeys(
        [entry(1, "/request", target="/request?id=123")],
        [entry(1, "/request", target="/request?id=456")],
    )
    assert comparison.common_prefix_length == 1
    assert not comparison.rows[0].different


def test_synthetic_fixture_diverges_at_help_vs_details():
    fixture = Path(__file__).parent / "fixtures" / "synthetic_journey.log"
    with fixture.open(encoding="utf-8") as lines:
        parsed = parse_lines(lines, "192.0.2.44")
    sessions = split_sessions(parsed.entries, 30)

    comparison = compare_application_journeys(sessions[0].entries, sessions[1].entries)

    assert comparison.common_prefix_length == 11
    divergence = comparison.rows[comparison.common_prefix_length]
    assert divergence.left.path == "/portal/help"
    assert divergence.right.path == "/portal/details"
