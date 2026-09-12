from pathlib import Path

from access_log_triage.analysis import is_static_resource, split_sessions
from access_log_triage.parser import parse_lines


def test_synthetic_journey_regression():
    fixture = Path(__file__).parent / "fixtures" / "synthetic_journey.log"
    with fixture.open(encoding="utf-8") as lines:
        result = parse_lines(lines, "192.0.2.44")

    sessions = split_sessions(result.entries, 30)
    assert result.parse_error_count == 1
    assert len(sessions) == 2
    assert sessions[0].static_requests == 1

    first = [entry.path for entry in sessions[0].entries if not is_static_resource(entry)]
    second = [entry.path for entry in sessions[1].entries if not is_static_resource(entry)]
    assert first[-3:] == ["/portal/contact", "/portal/help", "/portal/request"]
    assert second[-5:] == [
        "/portal/details", "/portal/payment", "/portal/document",
        "/portal/review", "/portal/complete",
    ]
