"""Run with:  python -m pytest"""
from datetime import datetime

from soc.detectors import Thresholds, run_all
from soc.generator import generate
from soc.parsers import parse_line, parse_logs

NOW = datetime(2026, 11, 25, 12, 0, 0)


def test_parse_ssh_failed():
    line = "Nov 25 10:00:01 web01 sshd[123]: Failed password for invalid user test from 203.0.113.5 port 5000 ssh2"
    row = parse_line(line, NOW)
    assert row["event"] == "failed_login"
    assert row["src_ip"] == "203.0.113.5"
    assert row["user"] == "test"
    assert row["status"] == "invalid_user"


def test_parse_web():
    line = '198.51.100.1 - - [25/Nov/2026:10:00:00 +0600] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"'
    row = parse_line(line, NOW)
    assert row["source"] == "Web" and row["status"] == "200" and row["user_agent"] == "curl/8.0"


def test_parse_firewall():
    line = ("Nov 25 10:00:00 fw01 kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.9 DST=10.0.0.5 "
            "LEN=44 PROTO=TCP SPT=40000 DPT=22 WINDOW=1024")
    row = parse_line(line, NOW)
    assert row["source"] == "Firewall" and row["dst_port"] == 22


def test_unknown_line_ignored():
    assert parse_line("hello world", NOW) is None


def test_all_attack_scenarios_detected():
    alerts = run_all(parse_logs(generate(end=NOW), now=NOW))
    found = set(zip(alerts["rule"], alerts["src_ip"]))
    expected = {
        ("SSH Brute Force", "203.0.113.45"),
        ("Possible Account Compromise", "203.0.113.45"),
        ("SSH Brute Force", "198.51.100.23"),
        ("Port Scan", "192.0.2.77"),
        ("SQL Injection", "198.51.100.88"),
        ("Cross-Site Scripting (XSS)", "203.0.113.99"),
        ("Directory Brute Force", "192.0.2.150"),
        ("Path Traversal", "198.51.100.200"),
        ("Command Injection", "198.51.100.200"),
    }
    assert expected <= found


def test_no_false_positives_on_normal_traffic():
    alerts = run_all(parse_logs(generate(end=NOW), now=NOW))
    normal = alerts[alerts["src_ip"].str.startswith(("10.", "172.16.", "100.64."))]
    assert normal.empty, normal


def test_thresholds_change_results():
    df = parse_logs(generate(end=NOW), now=NOW)
    strict = run_all(df, Thresholds(brute_force_attempts=100))
    assert "SSH Brute Force" not in set(strict["rule"])
