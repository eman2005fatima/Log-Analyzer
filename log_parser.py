"""Parsing utilities for cybersecurity log analysis."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional


APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>[^"]*?) (?P<protocol>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?$'
)

APACHE_ERROR_PATTERN = re.compile(
    r'^\[(?P<timestamp>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\] '
    r'\[(?P<level>emerg|alert|crit|error|warn|notice|info|debug)\] '
    r'(?P<message>.*)$',
    re.IGNORECASE,
)

SYSLOG_PATTERN = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
    r'(?P<host>\S+) (?P<program>[\w.\-/]+)(?:\[\d+\])?: '
    r'(?P<message>.*)$'
)

CUSTOM_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}) '
    r'\[(?P<level>ERROR|WARNING|WARN|INFO|DEBUG|CRITICAL)\] '
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) '
    r'(?P<message>.*)$',
    re.IGNORECASE,
)

IP_PATTERN = re.compile(r'\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b')
ISO_TIMESTAMP_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}'
    r'(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
)
APACHE_TIMESTAMP_PATTERN = re.compile(r'\[(?P<timestamp>\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]')
HTTP_REQUEST_PATTERN = re.compile(
    r'\b(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<path>/\S*)',
    re.IGNORECASE,
)
STATUS_CODE_PATTERNS = (
    re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^"]+"\s+(?P<status>[1-5]\d{2})\b', re.IGNORECASE),
    re.compile(r'\b(?:status|code|response)[=:\s]+(?P<status>[1-5]\d{2})\b', re.IGNORECASE),
    re.compile(r'\bHTTP/\d(?:\.\d)?["\s]+(?P<status>[1-5]\d{2})\b', re.IGNORECASE),
)
LEVEL_PATTERN = re.compile(r'\b(?P<level>ERROR|ERR|WARNING|WARN|INFO|DEBUG|CRITICAL|FAILED|FAILURE)\b', re.IGNORECASE)
STATUS_WORDS = {
    "error": "ERROR",
    "failed": "ERROR",
    "failure": "ERROR",
    "warn": "WARNING",
    "warning": "WARNING",
    "info": "INFO",
    "debug": "DEBUG",
}


@dataclass
class LogEntry:
    """Represents one parsed log line."""

    raw_line: str
    timestamp: Optional[datetime]
    ip_address: Optional[str]
    log_level: str
    status_code: Optional[int]
    message: str
    source_format: str
    path: Optional[str] = None
    method: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serializable representation of this log entry."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return data


def parse_log_lines(lines: Iterable[str]) -> List[LogEntry]:
    """Parse a sequence of raw log lines into LogEntry objects."""
    entries: List[LogEntry] = []
    for line in lines:
        clean_line = line.rstrip("\n")
        if clean_line.strip():
            entries.append(parse_log_line(clean_line))
    return entries


def parse_log_line(line: str) -> LogEntry:
    """Parse one log line by auto-detecting Apache, Syslog, custom, or unknown."""
    apache_match = APACHE_PATTERN.match(line)
    if apache_match:
        return _parse_apache(line, apache_match)

    apache_error_match = APACHE_ERROR_PATTERN.match(line)
    if apache_error_match:
        return _parse_apache_error(line, apache_error_match)

    syslog_match = SYSLOG_PATTERN.match(line)
    if syslog_match:
        return _parse_syslog(line, syslog_match)

    custom_match = CUSTOM_PATTERN.match(line)
    if custom_match:
        return _parse_custom(line, custom_match)

    return _parse_unknown(line)


def _parse_unknown(line: str) -> LogEntry:
    """Preserve an unmatched line while extracting any useful chart fields."""
    status_code = _extract_status_code(line)
    request = HTTP_REQUEST_PATTERN.search(line)
    method = request.group("method").upper() if request else None
    path = request.group("path") if request else None
    level = _extract_level(line)
    if level == "UNKNOWN" and status_code is not None:
        level = _level_from_status(status_code)

    return LogEntry(
        raw_line=line,
        timestamp=_extract_timestamp(line),
        ip_address=_extract_ip(line),
        log_level=level,
        status_code=status_code,
        message=line,
        source_format="unknown",
        path=path,
        method=method,
    )


def _parse_apache(line: str, match: re.Match[str]) -> LogEntry:
    timestamp = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")
    status_code = int(match.group("status"))
    path = match.group("path")
    message = f'{match.group("method")} {path} {match.group("protocol")}'
    return LogEntry(
        raw_line=line,
        timestamp=timestamp,
        ip_address=match.group("ip"),
        log_level=_level_from_status(status_code),
        status_code=status_code,
        message=message,
        source_format="apache",
        path=path,
        method=match.group("method"),
    )


def _parse_apache_error(line: str, match: re.Match[str]) -> LogEntry:
    timestamp = datetime.strptime(match.group("timestamp"), "%a %b %d %H:%M:%S %Y")
    level = _normalize_level(match.group("level"))
    message = match.group("message")
    return LogEntry(
        raw_line=line,
        timestamp=timestamp,
        ip_address=_extract_ip(message),
        log_level=level,
        status_code=None,
        message=message,
        source_format="apache",
    )


def _parse_syslog(line: str, match: re.Match[str]) -> LogEntry:
    timestamp = _parse_syslog_timestamp(match.group("timestamp"))
    message = match.group("message")
    return LogEntry(
        raw_line=line,
        timestamp=timestamp,
        ip_address=_extract_ip(message),
        log_level=_infer_level(message),
        status_code=None,
        message=message,
        source_format="syslog",
    )


def _parse_custom(line: str, match: re.Match[str]) -> LogEntry:
    timestamp = datetime.strptime(match.group("timestamp").replace("T", " "), "%Y-%m-%d %H:%M:%S")
    level = match.group("level").upper()
    if level == "WARN":
        level = "WARNING"
    return LogEntry(
        raw_line=line,
        timestamp=timestamp,
        ip_address=match.group("ip"),
        log_level=level,
        status_code=None,
        message=match.group("message"),
        source_format="custom",
    )


def _parse_syslog_timestamp(value: str) -> datetime:
    current_year = datetime.now().year
    return datetime.strptime(f"{current_year} {value}", "%Y %b %d %H:%M:%S")


def _extract_timestamp(text: str) -> Optional[datetime]:
    apache_match = APACHE_TIMESTAMP_PATTERN.search(text)
    if apache_match:
        return datetime.strptime(apache_match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")

    iso_match = ISO_TIMESTAMP_PATTERN.search(text)
    if iso_match:
        value = iso_match.group("timestamp").replace(",", ".").replace("Z", "+00:00")
        if len(value) >= 5 and value[-5] in "+-" and ":" not in value[-5:]:
            value = f"{value[:-2]}:{value[-2:]}"
        try:
            return datetime.fromisoformat(value.replace(" ", "T"))
        except ValueError:
            return None

    syslog_match = re.search(r'\b(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b', text)
    if syslog_match:
        return _parse_syslog_timestamp(syslog_match.group("timestamp"))

    return None


def _extract_ip(text: str) -> Optional[str]:
    match = IP_PATTERN.search(text)
    return match.group("ip") if match else None


def _extract_status_code(text: str) -> Optional[int]:
    for pattern in STATUS_CODE_PATTERNS:
        match = pattern.search(text)
        if match:
            status = int(match.group("status"))
            if 100 <= status <= 599:
                return status
    return None


def _extract_level(text: str) -> str:
    match = LEVEL_PATTERN.search(text)
    if not match:
        return "UNKNOWN"
    return _normalize_level(match.group("level"))


def _normalize_level(value: str) -> str:
    level = value.upper()
    if level in {"EMERG", "ALERT", "CRIT", "CRITICAL", "ERR", "ERROR", "FAILED", "FAILURE"}:
        return "ERROR"
    if level == "WARN":
        return "WARNING"
    if level == "NOTICE":
        return "INFO"
    return level


def _level_from_status(status_code: int) -> str:
    if status_code >= 500:
        return "ERROR"
    if status_code >= 400:
        return "WARNING"
    return "INFO"


def _infer_level(message: str) -> str:
    lowered = message.lower()
    for word, level in STATUS_WORDS.items():
        if word in lowered:
            return level
    return "INFO"
