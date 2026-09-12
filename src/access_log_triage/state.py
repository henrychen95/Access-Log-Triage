from __future__ import annotations

import secrets
from collections import defaultdict
from dataclasses import dataclass
from threading import Lock
from types import MappingProxyType
from typing import Mapping

from .models import LogEntry, ParseResult


@dataclass(frozen=True, slots=True)
class LoadedLog:
    id: str
    filename: str
    total_lines: int
    parse_error_count: int
    records: tuple[LogEntry, ...]
    records_by_ip: Mapping[str, tuple[LogEntry, ...]]

    def records_for(self, ip: str) -> tuple[LogEntry, ...]:
        return self.records_by_ip.get(ip, ())


def build_loaded_log(filename: str, parsed: ParseResult) -> LoadedLog:
    records = tuple(parsed.entries)
    index: defaultdict[str, list[LogEntry]] = defaultdict(list)
    for record in records:
        index[record.ip].append(record)

    return LoadedLog(
        id=secrets.token_urlsafe(24),
        filename=filename,
        total_lines=parsed.total_lines,
        parse_error_count=parsed.parse_error_count,
        records=records,
        records_by_ip=MappingProxyType(
            {ip: tuple(entries) for ip, entries in index.items()}
        ),
    )


class CurrentLogStore:
    """Thread-safe holder for the process's single loaded-log snapshot."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._current: LoadedLog | None = None

    def get(self) -> LoadedLog | None:
        with self._lock:
            return self._current

    def replace(self, loaded_log: LoadedLog) -> None:
        with self._lock:
            self._current = loaded_log

    def clear(self) -> None:
        with self._lock:
            self._current = None


current_log_store = CurrentLogStore()
