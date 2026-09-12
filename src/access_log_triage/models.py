from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class LogEntry:
    ip: str
    timestamp: datetime
    timezone: str
    method: str
    request_target: str
    path: str
    query_string: str
    protocol: str
    status: int
    response_bytes: int | None
    referer: str | None
    user_agent: str | None
    raw_line: str
    line_number: int


@dataclass(slots=True)
class ParseResult:
    entries: list[LogEntry]
    total_lines: int = 0
    parse_error_count: int = 0
