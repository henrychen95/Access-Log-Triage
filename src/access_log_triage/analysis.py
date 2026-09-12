from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from itertools import zip_longest
from pathlib import PurePosixPath
from typing import Iterable

from .models import LogEntry

STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
}


def is_static_resource(entry_or_path: LogEntry | str) -> bool:
    path = entry_or_path.path if isinstance(entry_or_path, LogEntry) else entry_or_path
    lowered = path.lower()
    suffix = PurePosixPath(lowered).suffix
    return (
        suffix in STATIC_EXTENSIONS
        or lowered == "/favicon.ico"
        or lowered.startswith("/apple-touch-icon")
        or lowered == "/assets"
        or lowered.startswith("/assets/")
    )


def is_static_noise(entry: LogEntry) -> bool:
    """Return whether a request is safe to hide as routine static noise."""
    return is_static_resource(entry) and entry.status < 400


def status_group(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "other"


def public_target(entry: LogEntry, hide_query_strings: bool = True) -> str:
    if hide_query_strings or not entry.query_string:
        return entry.path
    return f"{entry.path}?{entry.query_string}"


def redacted_raw_line(entry: LogEntry) -> str:
    """Return the raw line with only the request-target query removed."""
    if not entry.query_string:
        return entry.raw_line
    original_request = f'"{entry.method} {entry.request_target} {entry.protocol}"'
    redacted_request = f'"{entry.method} {entry.path} {entry.protocol}"'
    if original_request in entry.raw_line:
        return entry.raw_line.replace(original_request, redacted_request, 1)
    # A parser-produced entry should always contain the request triple. Avoid
    # returning potentially sensitive data if an entry was built elsewhere.
    return "[raw line hidden because its query string could not be safely redacted]"


def summarize_user_agent(user_agent: str | None) -> str:
    if not user_agent:
        return "Unknown"

    browser = "Unknown"
    for marker, name in (
        ("Edg/", "Edge"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
        ("Version/", "Safari"),
    ):
        if marker in user_agent:
            version = user_agent.split(marker, 1)[1].split()[0].split(".")[0]
            browser = f"{name} {version}"
            break

    if "Windows NT 6.1" in user_agent:
        os_name = "Windows 7"
    elif "Windows NT 10.0" in user_agent:
        os_name = "Windows 10/11"
    elif "Android" in user_agent:
        os_name = "Android"
    elif "iPhone" in user_agent or "iPad" in user_agent:
        os_name = "iOS"
    elif "Mac OS X" in user_agent:
        os_name = "macOS"
    elif "Linux" in user_agent:
        os_name = "Linux"
    else:
        os_name = "Unknown"

    if browser == "Unknown" and os_name == "Unknown":
        return "Unknown"
    return f"{browser} / {os_name}"


@dataclass(slots=True)
class Session:
    number: int
    entries: list[LogEntry]

    @property
    def start(self):
        return self.entries[0].timestamp

    @property
    def end(self):
        return self.entries[-1].timestamp

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    @property
    def total_requests(self) -> int:
        return len(self.entries)

    @property
    def application_requests(self) -> int:
        return sum(not is_static_resource(entry) for entry in self.entries)

    @property
    def static_requests(self) -> int:
        return self.total_requests - self.application_requests

    def method_count(self, method: str) -> int:
        return sum(entry.method == method for entry in self.entries)

    def group_count(self, group: str) -> int:
        return sum(status_group(entry.status) == group for entry in self.entries)

    @property
    def unique_paths(self) -> int:
        return len({entry.path for entry in self.entries})

    @property
    def user_agent_summary(self) -> str:
        agents = [entry.user_agent for entry in self.entries if entry.user_agent]
        return summarize_user_agent(Counter(agents).most_common(1)[0][0] if agents else None)


def split_sessions(entries: Iterable[LogEntry], gap_minutes: int = 30) -> list[Session]:
    if gap_minutes < 1:
        raise ValueError("Session gap must be at least 1 minute")
    ordered = sorted(entries, key=lambda entry: entry.timestamp)
    if not ordered:
        return []

    gap = timedelta(minutes=gap_minutes)
    groups: list[list[LogEntry]] = [[ordered[0]]]
    for entry in ordered[1:]:
        if entry.timestamp - groups[-1][-1].timestamp > gap:
            groups.append([])
        groups[-1].append(entry)
    return [Session(number=index, entries=group) for index, group in enumerate(groups, 1)]


@dataclass(frozen=True, slots=True)
class ComparisonRow:
    left: LogEntry | None
    right: LogEntry | None
    different: bool
    only_in_session: int | None


@dataclass(frozen=True, slots=True)
class JourneyComparison:
    left: tuple[LogEntry, ...]
    right: tuple[LogEntry, ...]
    common_prefix_length: int
    rows: tuple[ComparisonRow, ...]


def application_journey(entries: Iterable[LogEntry]) -> tuple[LogEntry, ...]:
    return tuple(entry for entry in entries if not is_static_resource(entry))


def compare_application_journeys(
    left_entries: Iterable[LogEntry], right_entries: Iterable[LogEntry]
) -> JourneyComparison:
    left = application_journey(left_entries)
    right = application_journey(right_entries)
    prefix_length = 0
    for left_entry, right_entry in zip(left, right):
        if (left_entry.method, left_entry.path) != (right_entry.method, right_entry.path):
            break
        prefix_length += 1

    rows = []
    for left_entry, right_entry in zip_longest(left, right):
        left_key = (left_entry.method, left_entry.path) if left_entry else None
        right_key = (right_entry.method, right_entry.path) if right_entry else None
        rows.append(
            ComparisonRow(
                left=left_entry,
                right=right_entry,
                different=left_key != right_key,
                only_in_session=2 if left_entry is None else (1 if right_entry is None else None),
            )
        )
    return JourneyComparison(left, right, prefix_length, tuple(rows))


def top_paths(entries: Iterable[LogEntry], limit: int = 15) -> list[tuple[str, int]]:
    paths = Counter(entry.path for entry in entries if not is_static_resource(entry))
    return paths.most_common(limit)


def format_duration(value: timedelta) -> str:
    seconds = max(0, int(value.total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    return f"{minutes}m {seconds:02d}s"
