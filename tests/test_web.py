import json
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from access_log_triage.main import app
from access_log_triage.state import current_log_store

client = TestClient(app)
FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_journey.log"


class TimelineRowParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self.journeys = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "details" and "request-row" in attributes.get("class", "").split():
            self.rows.append(attributes)
        if tag == "div" and "data-requests" in attributes:
            self.journeys.append(json.loads(attributes["data-requests"]))


@pytest.fixture(autouse=True)
def reset_loaded_log():
    current_log_store.clear()
    yield
    current_log_store.clear()


def upload_text(log_text: str, filename: str = "access.log"):
    return client.post(
        "/upload",
        files={"log_file": (filename, log_text.encode(), "text/plain")},
    )


def analyze_loaded(ip_address: str, session_gap: int = 30):
    loaded_log = current_log_store.get()
    assert loaded_log is not None
    return client.post(
        "/analyze",
        data={
            "log_id": loaded_log.id,
            "ip_address": ip_address,
            "session_gap": str(session_gap),
        },
    )


def analyze_text(log_text: str):
    upload_response = upload_text(log_text)
    assert upload_response.status_code == 200
    return analyze_loaded("192.0.2.1")


def log_line(second: int, path: str, status: int, method: str = "GET") -> str:
    return (
        f'192.0.2.1 - - [10/Sep/2026:13:00:{second:02d} +0000] '
        f'"{method} {path} HTTP/1.1" {status} 10 "-" "UA"'
    )


def timeline_rows(response):
    parser = TimelineRowParser()
    parser.feed(response.text)
    return parser.rows


def test_home_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "Access Log Triage" in response.text
    assert "Local only" in response.text
    assert 'rel="icon" type="image/svg+xml" href="http://testserver/static/favicon.svg"' in response.text
    assert client.get("/static/favicon.svg").headers["content-type"].startswith("image/svg+xml")
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_analyze_synthetic_fixture():
    with FIXTURE.open("rb") as log_file:
        upload_response = client.post(
            "/upload",
            files={"log_file": ("access.log", log_file, "text/plain")},
        )
    assert upload_response.status_code == 200
    response = analyze_loaded("192.0.2.44")
    assert response.status_code == 200
    assert "Session #1" in response.text
    assert "Session #2" in response.text
    assert "1 parser error" in response.text
    assert "/portal/complete" in response.text
    assert "Compare sessions" in response.text
    assert response.text.index('id="journey-compare"') < response.text.index('class="content-grid"')
    assert 'class="panel compare-wide"' in response.text
    parser = TimelineRowParser()
    parser.feed(response.text)
    assert all(request["path"] != "/assets/app.css" for journey in parser.journeys for request in journey)


def test_compare_is_hidden_for_a_single_session():
    response = analyze_text(log_line(1, "/only-session", 200))
    assert response.status_code == 200
    assert 'id="journey-compare"' not in response.text


def test_compare_selectors_include_all_three_sessions():
    log_text = "\n".join([
        log_line(1, "/first", 200),
        '192.0.2.1 - - [10/Sep/2026:14:00:01 +0000] "GET /second HTTP/1.1" 200 10 "-" "UA"',
        '192.0.2.1 - - [10/Sep/2026:15:00:01 +0000] "GET /third HTTP/1.1" 200 10 "-" "UA"',
    ])
    response = analyze_text(log_text)
    assert response.status_code == 200
    assert response.text.count("data-requests=") == 3
    assert response.text.count('value="3"') == 2


def test_static_errors_remain_visible_and_summary_uses_all_seven_requests():
    log_text = "\n".join(
        [
            log_line(1, "/application", 200, "POST"),
            log_line(2, "/favicon.ico", 200),
            log_line(3, "/assets/app.js", 200),
            log_line(4, "/images/logo.png", 200),
            log_line(5, "/assets/theme.css", 200),
            log_line(6, "/missing.ico", 404),
            log_line(7, "/assets/missing.js", 404),
        ]
    )
    response = analyze_text(log_text)
    assert response.status_code == 200

    # Summary remains based on the complete request set, outside UI filters.
    assert '<strong>7</strong><span>Total requests</span>' in response.text
    assert '<strong>1</strong><span>Application</span>' in response.text
    assert '<strong>6</strong><span>Static</span>' in response.text
    assert '<strong>1</strong><span>POST</span>' in response.text
    assert '<strong>2</strong><span>4xx</span>' in response.text
    assert '<strong>0</strong><span>5xx</span>' in response.text

    rows = timeline_rows(response)
    by_path = {row["data-path"]: row for row in rows}
    for path in ("/favicon.ico", "/assets/app.js", "/images/logo.png", "/assets/theme.css"):
        assert "static-noise" in by_path[path]["class"].split()
    for path in ("/missing.ico", "/assets/missing.js"):
        row = by_path[path]
        assert "static-request" in row["class"].split()
        assert "static-noise" not in row["class"].split()
        assert row["data-status-group"] == "4xx"

    # The 4XX button's status filter therefore selects both errors without the
    # static filter excluding either one.
    visible_4xx = [
        row for row in rows
        if row["data-status-group"] == "4xx"
        and (int(row["data-status"]) >= 400 or "static-request" not in row["class"].split())
    ]
    assert {row["data-path"] for row in visible_4xx} == {"/missing.ico", "/assets/missing.js"}


def test_5xx_filter_includes_all_static_errors():
    response = analyze_text("\n".join([
        log_line(1, "/assets/broken.png", 500),
        log_line(2, "/assets/font.woff2", 503),
        log_line(3, "/application", 200),
    ]))
    rows = timeline_rows(response)
    visible_5xx = [
        row for row in rows
        if row["data-status-group"] == "5xx"
        and (int(row["data-status"]) >= 400 or "static-request" not in row["class"].split())
    ]
    assert {row["data-path"] for row in visible_5xx} == {
        "/assets/broken.png", "/assets/font.woff2"
    }
    assert all("static-noise" not in row["class"].split() for row in visible_5xx)


def test_invalid_ip_has_clear_error():
    upload_text(log_line(1, "/", 200))
    response = analyze_loaded("192.0.2.999")
    assert response.status_code == 400
    assert "valid IPv4 or IPv6" in response.text


def test_log_content_is_html_escaped():
    malicious = (
        '192.0.2.1 - - [10/Sep/2026:13:00:00 +0000] '
        '"GET /&lt;probe&gt; HTTP/1.1" 200 1 "-" "<script>alert(1)</script>"\n'
    )
    response = analyze_text(malicious)
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
