import pytest

from access_log_triage.analysis import (
    is_static_noise,
    is_static_resource,
    public_target,
    redacted_raw_line,
    status_group,
)
from access_log_triage.parser import parse_line, parse_lines


def make_line(ip="192.0.2.4", target="/page?token=synthetic-value", status=200):
    return f'{ip} - - [10/Sep/2026:13:00:00 +0800] "GET {target} HTTP/1.1" {status} 10 "-" "UA"'


def test_ip_filter_is_exact_not_substring_or_prefix():
    result = parse_lines(
        [make_line(), make_line("192.0.2.40"), make_line("192.0.2.5")],
        target_ip="192.0.2.4",
    )
    assert [entry.ip for entry in result.entries] == ["192.0.2.4"]


def test_ipv6_filter_uses_address_equality():
    result = parse_lines(
        [make_line("2001:db8::1"), make_line("2001:db8::10")],
        target_ip="2001:0db8:0:0:0:0:0:1",
    )
    assert len(result.entries) == 1
    assert result.entries[0].ip == "2001:db8::1"


def test_static_resource_detection():
    for path in ("/site.css", "/app.JS", "/img/a.png", "/x/icon.svg", "/fonts/a.woff2", "/favicon.ico", "/apple-touch-icon-180.png", "/assets/build/app"):
        assert is_static_resource(path), path
    for path in ("/portal/request", "/api/assets-report", "/file.css/route"):
        assert not is_static_resource(path), path


@pytest.mark.parametrize(
    ("path", "status", "expected_noise"),
    [
        ("/favicon.ico", 200, True),
        ("/assets/app.js", 200, True),
        ("/favicon.ico", 404, False),
        ("/assets/app.js", 404, False),
        ("/images/missing.png", 500, False),
    ],
)
def test_only_successful_static_requests_are_hideable_noise(path, status, expected_noise):
    entry = parse_line(make_line(target=path, status=status))
    assert entry is not None
    assert is_static_resource(entry)
    assert is_static_noise(entry) is expected_noise


def test_status_groups():
    assert status_group(204) == "2xx"
    assert status_group(302) == "3xx"
    assert status_group(404) == "4xx"
    assert status_group(503) == "5xx"
    assert status_group(101) == "other"


def test_query_string_is_hidden_by_default():
    entry = parse_line(make_line())
    assert entry is not None
    assert public_target(entry) == "/page"
    assert "synthetic-value" not in public_target(entry)
    assert public_target(entry, hide_query_strings=False) == "/page?token=synthetic-value"
    assert "token=synthetic-value" not in redacted_raw_line(entry)
    assert '"GET /page HTTP/1.1"' in redacted_raw_line(entry)
