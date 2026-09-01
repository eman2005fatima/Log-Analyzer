from datetime import datetime, timedelta

from log_analyzer import LogAnalyzer
from log_parser import LogEntry


def make_entry(ip, timestamp, message="ok", status_code=None, path=None):
    return LogEntry(
        raw_line=message,
        timestamp=timestamp,
        ip_address=ip,
        log_level="INFO",
        status_code=status_code,
        message=message,
        source_format="custom",
        path=path,
    )


def test_brute_force_detection_triggers():
    base = datetime(2026, 7, 9, 10, 0, 0)
    entries = [
        make_entry("203.0.113.45", base + timedelta(seconds=i * 5), "Failed password for user root")
        for i in range(6)
    ]
    analyzer = LogAnalyzer(entries, {"failed_auth_threshold": 5, "failed_auth_window_seconds": 60})

    findings = analyzer.detect_brute_force()

    assert len(findings) == 1
    assert findings[0]["type"] == "brute_force_login"
    assert findings[0]["count"] == 6


def test_brute_force_detection_does_not_trigger_below_threshold():
    base = datetime(2026, 7, 9, 10, 0, 0)
    entries = [
        make_entry("203.0.113.45", base + timedelta(seconds=i * 5), "Failed password for user root")
        for i in range(5)
    ]
    analyzer = LogAnalyzer(entries, {"failed_auth_threshold": 5, "failed_auth_window_seconds": 60})

    assert analyzer.detect_brute_force() == []


def test_excessive_404_detection_triggers():
    base = datetime(2026, 7, 9, 10, 0, 0)
    entries = [
        make_entry("198.51.100.23", base + timedelta(seconds=i * 4), "GET missing", 404, f"/missing-{i}")
        for i in range(9)
    ]
    analyzer = LogAnalyzer(entries, {"not_found_threshold": 8, "not_found_window_seconds": 60})

    findings = analyzer.detect_excessive_404()

    assert len(findings) == 1
    assert findings[0]["type"] == "excessive_404"
    assert findings[0]["count"] == 9


def test_excessive_404_detection_does_not_trigger_for_repeated_same_path():
    base = datetime(2026, 7, 9, 10, 0, 0)
    entries = [
        make_entry("198.51.100.23", base + timedelta(seconds=i * 4), "GET missing", 404, "/same")
        for i in range(12)
    ]
    analyzer = LogAnalyzer(entries, {"not_found_threshold": 8, "not_found_window_seconds": 60})

    assert analyzer.detect_excessive_404() == []


def test_rapid_request_rate_detection_triggers():
    base = datetime(2026, 7, 9, 10, 0, 0)
    entries = [
        make_entry("192.0.2.10", base + timedelta(seconds=i), "GET /")
        for i in range(31)
    ]
    analyzer = LogAnalyzer(entries, {"request_rate_threshold_per_minute": 30})

    findings = analyzer.detect_rapid_request_rate()

    assert len(findings) == 1
    assert findings[0]["type"] == "rapid_request_rate"
    assert findings[0]["count"] == 31


def test_rapid_request_rate_detection_does_not_trigger_at_threshold():
    base = datetime(2026, 7, 9, 10, 0, 0)
    entries = [
        make_entry("192.0.2.10", base + timedelta(seconds=i), "GET /")
        for i in range(30)
    ]
    analyzer = LogAnalyzer(entries, {"request_rate_threshold_per_minute": 30})

    assert analyzer.detect_rapid_request_rate() == []


def test_error_burst_detection_triggers_without_ip_addresses():
    base = datetime(2026, 7, 9, 10, 0, 0)
    entries = [
        make_entry(None, base + timedelta(seconds=i * 3), "apache module error")
        for i in range(11)
    ]
    for entry in entries:
        entry.log_level = "ERROR"
    analyzer = LogAnalyzer(entries, {"error_burst_threshold": 10, "error_burst_window_seconds": 60})

    findings = analyzer.detect_error_burst()

    assert len(findings) == 1
    assert findings[0]["ip"] == "system"
    assert findings[0]["type"] == "error_burst"


def test_error_burst_detection_does_not_trigger_below_threshold():
    base = datetime(2026, 7, 9, 10, 0, 0)
    entries = [
        make_entry(None, base + timedelta(seconds=i * 3), "apache module error")
        for i in range(10)
    ]
    for entry in entries:
        entry.log_level = "ERROR"
    analyzer = LogAnalyzer(entries, {"error_burst_threshold": 10, "error_burst_window_seconds": 60})

    assert analyzer.detect_error_burst() == []


def test_statistics_include_expected_counts():
    base = datetime(2026, 7, 9, 10, 0, 0)
    entries = [
        make_entry("192.0.2.10", base, "GET /", 200, "/"),
        make_entry("192.0.2.10", base + timedelta(hours=1), "GET /missing", 404, "/missing"),
        make_entry(None, None, "bad line"),
    ]
    entries[-1].source_format = "unknown"
    analyzer = LogAnalyzer(entries)
    stats = analyzer.statistics()

    assert stats["total_lines"] == 3
    assert stats["unparseable_lines"] == 1
    assert stats["unique_ips"] == 1
    assert stats["status_codes"]["classes"]["2xx"] == 1
    assert stats["status_codes"]["classes"]["4xx"] == 1
