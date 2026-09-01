from log_parser import parse_log_line, parse_log_lines


def test_valid_apache_line():
    line = '192.0.2.1 - - [09/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    entry = parse_log_line(line)

    assert entry.source_format == "apache"
    assert entry.ip_address == "192.0.2.1"
    assert entry.status_code == 200
    assert entry.path == "/index.html"
    assert entry.log_level == "INFO"


def test_valid_apache_error_loghub_line():
    line = "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6"
    entry = parse_log_line(line)

    assert entry.source_format == "apache"
    assert entry.timestamp is not None
    assert entry.log_level == "ERROR"
    assert entry.status_code is None
    assert "workerEnv" in entry.message


def test_valid_syslog_line():
    line = "Jul  9 10:05:00 authbox sshd[2210]: Failed password for invalid user admin from 203.0.113.45 port 50100 ssh2"
    entry = parse_log_line(line)

    assert entry.source_format == "syslog"
    assert entry.ip_address == "203.0.113.45"
    assert entry.log_level == "ERROR"
    assert "Failed password" in entry.message


def test_malformed_line_is_preserved_as_unknown():
    line = "not a parseable log line"
    entry = parse_log_line(line)

    assert entry.source_format == "unknown"
    assert entry.raw_line == line
    assert entry.message == line


def test_unknown_line_still_extracts_chartable_fields():
    line = '2026-07-09T12:30:00Z edge-node 192.0.2.55 GET /hidden HTTP/1.1 status=404'
    entry = parse_log_line(line)

    assert entry.source_format == "unknown"
    assert entry.timestamp is not None
    assert entry.ip_address == "192.0.2.55"
    assert entry.status_code == 404
    assert entry.path == "/hidden"
    assert entry.log_level == "WARNING"


def test_unknown_line_does_not_treat_ip_octet_as_status_code():
    entry = parse_log_line("2026-07-09 12:30:00 firewall allowed connection from 192.0.2.55")

    assert entry.source_format == "unknown"
    assert entry.ip_address == "192.0.2.55"
    assert entry.status_code is None


def test_empty_input_returns_no_entries():
    assert parse_log_lines([]) == []
    assert parse_log_lines(["", "   "]) == []


def test_valid_custom_line():
    entry = parse_log_line("2026-07-09 10:08:40 [ERROR] 10.0.0.12 Login failed for service account")

    assert entry.source_format == "custom"
    assert entry.ip_address == "10.0.0.12"
    assert entry.log_level == "ERROR"
