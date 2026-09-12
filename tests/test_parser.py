from access_log_triage.parser import parse_line, parse_lines


BASE = '192.0.2.44 - - [10/Sep/2026:13:22:23 +0800] "{request}" {status} {size}{tail}'


def line(request="GET /portal/request HTTP/1.1", status=200, size="1109", tail=' "-" "Mozilla/5.0"'):
    return BASE.format(request=request, status=status, size=size, tail=tail)


def test_combined_ipv4_http11_get():
    entry = parse_line(line())
    assert entry is not None
    assert entry.ip == "192.0.2.44"
    assert entry.method == "GET"
    assert entry.protocol == "HTTP/1.1"
    assert entry.path == "/portal/request"
    assert entry.status == 200
    assert entry.response_bytes == 1109
    assert entry.referer is None
    assert entry.user_agent == "Mozilla/5.0"
    assert entry.timezone == "+0800"


def test_http2_post_and_query_string():
    entry = parse_line(line("POST /verify?token=synthetic-value&id=7 HTTP/2.0"))
    assert entry is not None
    assert entry.method == "POST"
    assert entry.protocol == "HTTP/2.0"
    assert entry.request_target == "/verify?token=synthetic-value&id=7"
    assert entry.path == "/verify"
    assert entry.query_string == "token=synthetic-value&id=7"


def test_http10_and_http2_are_supported():
    assert parse_line(line("HEAD / HTTP/1.0")).protocol == "HTTP/1.0"
    assert parse_line(line("OPTIONS * HTTP/2")).protocol == "HTTP/2"


def test_ipv6_and_missing_combined_fields():
    raw = '2001:db8::1 - - [10/Sep/2026:13:22:23 +0000] "PUT /api/item HTTP/1.1" 204 -'
    entry = parse_line(raw)
    assert entry is not None
    assert entry.ip == "2001:db8::1"
    assert entry.method == "PUT"
    assert entry.response_bytes is None
    assert entry.referer is None
    assert entry.user_agent is None


def test_missing_user_agent_but_referer_present():
    entry = parse_line(line(tail=' "https://example.test/from"'))
    assert entry is not None
    assert entry.referer == "https://example.test/from"
    assert entry.user_agent is None


def test_other_methods_and_unusual_url_characters():
    for method in ("PATCH", "DELETE"):
        entry = parse_line(line(f"{method} /資料/%E6%B8%AC%E8%A9%A6;v=1 HTTP/1.1"))
        assert entry is not None
        assert entry.method == method
        assert entry.path == "/資料/%E6%B8%AC%E8%A9%A6;v=1"


def test_malformed_line_is_counted_and_processing_continues():
    result = parse_lines(["not a log line\n", line() + "\n"])
    assert result.total_lines == 2
    assert result.parse_error_count == 1
    assert len(result.entries) == 1
    assert result.entries[0].line_number == 2


def test_escaped_quote_in_user_agent():
    entry = parse_line(line(tail=r' "-" "Agent \"quoted\""'))
    assert entry is not None
    assert entry.user_agent == 'Agent "quoted"'
