"""Analysis and anomaly detection for parsed security logs."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple

from log_parser import LogEntry


DEFAULT_CONFIG = {
    "failed_auth_threshold": 5,
    "failed_auth_window_seconds": 60,
    "not_found_threshold": 8,
    "not_found_window_seconds": 60,
    "request_rate_threshold_per_minute": 30,
    "error_burst_threshold": 10,
    "error_burst_window_seconds": 60,
}

FAILED_AUTH_TERMS = ("failed password", "authentication failure", "login failed", "failed login")


class LogAnalyzer:
    """Computes statistics and security anomalies from parsed log entries."""

    def __init__(self, entries: List[LogEntry], config: Optional[Dict[str, int]] = None):
        self.entries = entries
        self.config = dict(DEFAULT_CONFIG)
        if config:
            self.config.update(config)

    def statistics(self) -> Dict[str, object]:
        """Return dashboard-ready statistics for all parsed entries."""
        total_lines = len(self.entries)
        unparseable = sum(1 for entry in self.entries if entry.source_format == "unknown")
        ip_counts = Counter(entry.ip_address for entry in self.entries if entry.ip_address)
        level_counts = Counter(entry.log_level for entry in self.entries if entry.log_level)

        return {
            "total_lines": total_lines,
            "parsed_lines": total_lines - unparseable,
            "unparseable_lines": unparseable,
            "parsed_percent": round(((total_lines - unparseable) / total_lines) * 100, 2) if total_lines else 0,
            "unique_ips": len(ip_counts),
            "top_ips": [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(10)],
            "requests_per_hour": self._requests_per_hour(),
            "status_codes": self._status_codes(),
            "log_levels": dict(level_counts),
            "source_formats": dict(Counter(entry.source_format for entry in self.entries)),
        }

    def anomalies(self) -> List[Dict[str, object]]:
        """Return all detected anomaly records sorted by severity and count."""
        findings = []
        findings.extend(self.detect_brute_force())
        findings.extend(self.detect_excessive_404())
        findings.extend(self.detect_rapid_request_rate())
        findings.extend(self.detect_error_burst())
        order = {"high": 0, "medium": 1, "low": 2}
        return sorted(findings, key=lambda item: (order[item["severity"]], -int(item["count"]), item["ip"]))

    def entries_as_dicts(self) -> List[Dict[str, object]]:
        """Return all log entries as JSON-serializable dictionaries."""
        return [entry.to_dict() for entry in self.entries]

    def report(self) -> Dict[str, object]:
        """Return the complete analysis report."""
        anomalies = self.anomalies()
        return {
            "statistics": {**self.statistics(), "anomaly_count": len(anomalies)},
            "anomalies": anomalies,
            "entries": self.entries_as_dicts(),
        }

    def detect_brute_force(self) -> List[Dict[str, object]]:
        """Detect many failed authentication attempts from one IP in a sliding window."""
        events_by_ip: Dict[str, List[datetime]] = defaultdict(list)
        for entry in self.entries:
            if entry.ip_address and entry.timestamp and _looks_like_failed_auth(entry.message):
                events_by_ip[entry.ip_address].append(_naive(entry.timestamp))

        threshold = int(self.config["failed_auth_threshold"])
        window_seconds = int(self.config["failed_auth_window_seconds"])
        return self._detect_count_window(
            events_by_ip,
            threshold,
            window_seconds,
            "brute_force_login",
            "failed authentication attempts",
        )

    def detect_excessive_404(self) -> List[Dict[str, object]]:
        """Detect one IP requesting many different 404 paths in a short window."""
        grouped: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        for entry in self.entries:
            if entry.ip_address and entry.timestamp and entry.status_code == 404:
                grouped[entry.ip_address].append((_naive(entry.timestamp), entry.path or entry.message))

        threshold = int(self.config["not_found_threshold"])
        window_seconds = int(self.config["not_found_window_seconds"])
        anomalies: List[Dict[str, object]] = []
        for ip, events in grouped.items():
            events.sort(key=lambda item: item[0])
            window: Deque[Tuple[datetime, str]] = deque()
            best_paths: Set[str] = set()
            best_start: Optional[datetime] = None
            best_end: Optional[datetime] = None

            for timestamp, path in events:
                window.append((timestamp, path))
                while window and (timestamp - window[0][0]).total_seconds() > window_seconds:
                    window.popleft()
                paths = {item[1] for item in window}
                if len(paths) > len(best_paths):
                    best_paths = paths
                    best_start = window[0][0]
                    best_end = timestamp

            if len(best_paths) > threshold and best_start and best_end:
                anomalies.append(
                    self._make_anomaly(
                        ip,
                        "excessive_404",
                        len(best_paths),
                        threshold,
                        best_start,
                        best_end,
                        f"{ip} requested {len(best_paths)} unique missing paths within {window_seconds} seconds.",
                    )
                )
        return anomalies

    def detect_rapid_request_rate(self) -> List[Dict[str, object]]:
        """Detect one IP exceeding the configured request count per 60 seconds."""
        events_by_ip: Dict[str, List[datetime]] = defaultdict(list)
        for entry in self.entries:
            if entry.ip_address and entry.timestamp:
                events_by_ip[entry.ip_address].append(_naive(entry.timestamp))

        threshold = int(self.config["request_rate_threshold_per_minute"])
        return self._detect_count_window(
            events_by_ip,
            threshold,
            60,
            "rapid_request_rate",
            "requests per minute",
        )

    def detect_error_burst(self) -> List[Dict[str, object]]:
        """Detect a burst of error-level events even when logs do not include IP addresses."""
        events = [
            _naive(entry.timestamp)
            for entry in self.entries
            if entry.timestamp and entry.log_level in {"ERROR", "CRITICAL"}
        ]
        if not events:
            return []

        grouped = {"system": events}
        threshold = int(self.config["error_burst_threshold"])
        window_seconds = int(self.config["error_burst_window_seconds"])
        return self._detect_count_window(
            grouped,
            threshold,
            window_seconds,
            "error_burst",
            "error-level log events",
        )

    def _requests_per_hour(self) -> List[Dict[str, object]]:
        buckets = Counter()
        for entry in self.entries:
            if entry.timestamp:
                hour = _naive(entry.timestamp).replace(minute=0, second=0, microsecond=0)
                buckets[hour.isoformat(timespec="minutes")] += 1
        return [{"hour": hour, "count": buckets[hour]} for hour in sorted(buckets)]

    def _status_codes(self) -> Dict[str, object]:
        exact = Counter(str(entry.status_code) for entry in self.entries if entry.status_code)
        classes = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
        for entry in self.entries:
            if entry.status_code is None:
                continue
            bucket = f"{entry.status_code // 100}xx"
            if bucket in classes:
                classes[bucket] += 1
            else:
                classes["other"] += 1
        return {"classes": classes, "exact": dict(exact)}

    def _detect_count_window(
        self,
        events_by_ip: Dict[str, List[datetime]],
        threshold: int,
        window_seconds: int,
        anomaly_type: str,
        label: str,
    ) -> List[Dict[str, object]]:
        anomalies: List[Dict[str, object]] = []
        for ip, events in events_by_ip.items():
            events.sort()
            window: Deque[datetime] = deque()
            best_count = 0
            best_start: Optional[datetime] = None
            best_end: Optional[datetime] = None

            for timestamp in events:
                window.append(timestamp)
                while window and (timestamp - window[0]).total_seconds() > window_seconds:
                    window.popleft()
                if len(window) > best_count:
                    best_count = len(window)
                    best_start = window[0]
                    best_end = timestamp

            if best_count > threshold and best_start and best_end:
                anomalies.append(
                    self._make_anomaly(
                        ip,
                        anomaly_type,
                        best_count,
                        threshold,
                        best_start,
                        best_end,
                        f"{ip} generated {best_count} {label} within {window_seconds} seconds.",
                    )
                )
        return anomalies

    def _make_anomaly(
        self,
        ip: str,
        anomaly_type: str,
        count: int,
        threshold: int,
        start: datetime,
        end: datetime,
        description: str,
    ) -> Dict[str, object]:
        return {
            "ip": ip,
            "type": anomaly_type,
            "severity": _severity(count, threshold),
            "count": count,
            "time_window": {
                "start": start.isoformat(timespec="seconds"),
                "end": end.isoformat(timespec="seconds"),
                "seconds": max(1, int((end - start).total_seconds())),
            },
            "description": description,
        }


def _looks_like_failed_auth(message: str) -> bool:
    lowered = message.lower()
    return any(term in lowered for term in FAILED_AUTH_TERMS)


def _severity(count: int, threshold: int) -> str:
    ratio = count / max(threshold, 1)
    if ratio >= 2:
        return "high"
    if ratio >= 1.4:
        return "medium"
    return "low"


def _naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.replace(tzinfo=None)
