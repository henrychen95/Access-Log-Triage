from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from access_log_triage.main import app
from access_log_triage.parser import parse_binary_stream
from access_log_triage.state import current_log_store

client = TestClient(app)


def line(ip: str, path: str, second: int = 1) -> str:
    return (
        f'{ip} - - [10/Sep/2026:13:00:{second:02d} +0000] '
        f'"GET {path} HTTP/1.1" 200 10 "-" "UA"'
    )


LOG_A = "\n".join([
    line("192.0.2.10", "/from-a", 1),
    line("192.0.2.20", "/from-b", 2),
    "malformed regression line",
])
LOG_B = line("198.51.100.30", "/replacement", 1)


@pytest.fixture(autouse=True)
def reset_loaded_log():
    current_log_store.clear()
    yield
    current_log_store.clear()


def upload(content: str, filename: str = "sample-access.log"):
    return client.post(
        "/upload",
        files={"log_file": (filename, content.encode(), "text/plain")},
    )


def analyze(ip: str, gap: int = 30):
    loaded = current_log_store.get()
    assert loaded is not None
    return client.post(
        "/analyze",
        data={"log_id": loaded.id, "ip_address": ip, "session_gap": str(gap)},
    )


def test_upload_once_establishes_current_log_and_metadata():
    response = upload(LOG_A)
    loaded = current_log_store.get()

    assert response.status_code == 200
    assert loaded is not None
    assert loaded.filename == "sample-access.log"
    assert loaded.total_lines == 3
    assert loaded.parse_error_count == 1
    assert len(loaded.records) == 2
    assert loaded.records_for("192.0.2.10")[0] is loaded.records[0]
    assert "Loaded log" in response.text
    assert "3 lines · 1 parser error" in response.text


def test_analyze_ip_a_then_ip_b_without_another_upload():
    upload(LOG_A)
    loaded_id = current_log_store.get().id

    response_a = analyze("192.0.2.10")
    response_b = analyze("192.0.2.20")

    assert response_a.status_code == 200
    assert "/from-a" in response_a.text
    assert "/from-b" not in response_a.text
    assert response_b.status_code == 200
    assert "/from-b" in response_b.text
    assert "/from-a" not in response_b.text
    assert current_log_store.get().id == loaded_id


def test_ip_not_found_keeps_loaded_log_available():
    upload(LOG_A)
    loaded_id = current_log_store.get().id

    response = analyze("203.0.113.99")

    assert response.status_code == 200
    assert "No requests found for 203.0.113.99 in the currently loaded log." in response.text
    assert "sample-access.log" in response.text
    assert current_log_store.get().id == loaded_id
    assert "/from-a" in analyze("192.0.2.10").text


def test_successful_replace_atomically_switches_to_new_log():
    upload(LOG_A, "log-a.log")
    old_id = current_log_store.get().id
    replace_page = client.get("/replace")
    assert current_log_store.get().id == old_id
    assert "Currently loaded: log-a.log" in replace_page.text

    upload(LOG_B, "log-b.log")
    loaded = current_log_store.get()

    assert loaded.id != old_id
    assert loaded.filename == "log-b.log"
    assert "/replacement" in analyze("198.51.100.30").text
    assert "No requests found for 192.0.2.10" in analyze("192.0.2.10").text


def test_failed_replace_preserves_previous_log():
    upload(LOG_A, "log-a.log")
    old_id = current_log_store.get().id

    response = upload("this is not an access log", "broken.log")

    assert response.status_code == 400
    assert "no valid Apache access-log records" in response.text
    assert current_log_store.get().id == old_id
    assert current_log_store.get().filename == "log-a.log"
    assert "/from-a" in analyze("192.0.2.10").text


def test_analyzing_multiple_ips_does_not_reparse_uploaded_log():
    with patch("access_log_triage.main.parse_binary_stream", wraps=parse_binary_stream) as parser:
        upload(LOG_A)
        assert parser.call_count == 1
        analyze("192.0.2.10")
        analyze("192.0.2.20")
        analyze("203.0.113.99")
        analyze("192.0.2.10")
        assert parser.call_count == 1
