from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import BinaryIO, Iterable
from urllib.parse import urlsplit

from .models import LogEntry, ParseResult

# Combined Log Format, with the referer and user-agent tail optional so that
# Common Log Format and partially configured Combined logs remain usable.
_LOG_RE = re.compile(
    r'''^(?P<ip>\S+)\s+\S+\s+\S+\s+'''
    r'''\[(?P<timestamp>[^\]]+)\]\s+'''
    r'''"(?P<method>[A-Za-z]+)\s+(?P<target>\S+)\s+'''
    r'''(?P<protocol>HTTP/(?:1\.0|1\.1|2(?:\.0)?))"\s+'''
    r'''(?P<status>\d{3})\s+(?P<bytes>\d+|-)'''
    r'''(?:\s+"(?P<referer>(?:\\.|[^"])*)"'''
    r'''(?:\s+"(?P<user_agent>(?:\\.|[^"])*)")?)?\s*$'''
)


class FileTooLargeError(ValueError):
    pass


def _apache_unescape(value: str | None) -> str | None:
    if value is None or value == "-":
        return None
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def parse_line(line: str, line_number: int = 1) -> LogEntry | None:
    raw_line = line.rstrip("\r\n")
    match = _LOG_RE.match(raw_line)
    if not match:
        return None

    fields = match.groupdict()
    try:
        parsed_ip = ipaddress.ip_address(fields["ip"])
        timestamp = datetime.strptime(fields["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
        status = int(fields["status"])
        response_bytes = None if fields["bytes"] == "-" else int(fields["bytes"])
    except (ValueError, OverflowError):
        return None

    target = _apache_unescape(fields["target"]) or ""
    split_target = urlsplit(target)
    path = split_target.path or ("*" if target == "*" else "/")

    return LogEntry(
        ip=str(parsed_ip),
        timestamp=timestamp,
        timezone=timestamp.strftime("%z"),
        method=fields["method"].upper(),
        request_target=target,
        path=path,
        query_string=split_target.query,
        protocol=fields["protocol"],
        status=status,
        response_bytes=response_bytes,
        referer=_apache_unescape(fields["referer"]),
        user_agent=_apache_unescape(fields["user_agent"]),
        raw_line=raw_line,
        line_number=line_number,
    )


def parse_lines(lines: Iterable[str], target_ip: str | None = None) -> ParseResult:
    wanted = ipaddress.ip_address(target_ip) if target_ip is not None else None
    result = ParseResult(entries=[])
    for line_number, line in enumerate(lines, 1):
        result.total_lines += 1
        entry = parse_line(line, line_number)
        if entry is None:
            result.parse_error_count += 1
            continue
        if wanted is None or ipaddress.ip_address(entry.ip) == wanted:
            result.entries.append(entry)
    return result


def parse_binary_stream(
    stream: BinaryIO, target_ip: str | None = None, max_bytes: int = 150 * 1024 * 1024
) -> ParseResult:
    wanted = ipaddress.ip_address(target_ip) if target_ip is not None else None
    result = ParseResult(entries=[])
    bytes_read = 0

    for line_number, raw_line in enumerate(stream, 1):
        bytes_read += len(raw_line)
        if bytes_read > max_bytes:
            raise FileTooLargeError(f"Log exceeds the {max_bytes // (1024 * 1024)} MiB limit")
        result.total_lines += 1
        line = raw_line.decode("utf-8", errors="replace")
        entry = parse_line(line, line_number)
        if entry is None:
            result.parse_error_count += 1
            continue
        if wanted is None or ipaddress.ip_address(entry.ip) == wanted:
            result.entries.append(entry)

    return result
