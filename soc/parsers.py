"""
Log parsers.

Supported formats (detected automatically, line by line):
  * SSH auth log       (OpenSSH via syslog, e.g. /var/log/auth.log)
  * Web access log     (Apache / Nginx "combined" format)
  * Firewall log       (Linux UFW / iptables kernel log)
"""
import re
from datetime import datetime, timedelta

import pandas as pd

SYSLOG_TS = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

SSH_RE = re.compile(SYSLOG_TS + r"\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$")
SSH_FAILED = re.compile(r"Failed \S+ for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)")
SSH_OK = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)")

WEB_RE = re.compile(
    r'^(?P<ip>[\d.a-fA-F:]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

FW_RE = re.compile(
    SYSLOG_TS + r"\s+\S+\s+kernel:.*?\[UFW (?P<action>BLOCK|ALLOW|AUDIT)\].*?"
    r"SRC=(?P<ip>\S+)\s+DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)(?:.*?DPT=(?P<dpt>\d+))?"
)

COLUMNS = ["timestamp", "source", "event", "src_ip", "user", "status",
           "method", "path", "user_agent", "dst_port", "raw"]


def _syslog_time(ts: str, now: datetime) -> datetime:
    """Syslog lines have no year: assume this year, or last year if that is in the future."""
    t = datetime.strptime(f"{now.year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
    if t > now + timedelta(days=1):
        t = t.replace(year=now.year - 1)
    return t


def parse_line(line: str, now: datetime) -> dict | None:
    line = line.strip()
    if not line:
        return None

    m = SSH_RE.search(line)
    if m:
        msg = m["msg"]
        f = SSH_FAILED.search(msg)
        ok = SSH_OK.search(msg) if not f else None
        if not (f or ok):
            return None  # other sshd noise (disconnects, etc.)
        hit = f or ok
        return {
            "timestamp": _syslog_time(m["ts"], now), "source": "SSH",
            "event": "failed_login" if f else "successful_login",
            "src_ip": hit["ip"], "user": hit["user"],
            "status": ("invalid_user" if f and f["invalid"] else "failed") if f else "accepted",
            "raw": line,
        }

    m = WEB_RE.match(line)
    if m:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        return {
            "timestamp": ts, "source": "Web", "event": "http_request",
            "src_ip": m["ip"], "status": m["status"], "method": m["method"],
            "path": m["path"], "user_agent": m["ua"] or "", "raw": line,
        }

    m = FW_RE.search(line)
    if m:
        return {
            "timestamp": _syslog_time(m["ts"], now), "source": "Firewall",
            "event": f"fw_{m['action'].lower()}", "src_ip": m["ip"],
            "status": m["action"], "dst_port": int(m["dpt"]) if m["dpt"] else None,
            "raw": line,
        }
    return None


def parse_logs(texts: dict[str, str] | list[str], now: datetime | None = None) -> pd.DataFrame:
    """Parse one or more log texts into a single, time-sorted events DataFrame."""
    now = now or datetime.now()
    if isinstance(texts, dict):
        texts = list(texts.values())
    rows = []
    for text in texts:
        for line in text.splitlines():
            row = parse_line(line, now)
            if row:
                rows.append(row)
    df = pd.DataFrame(rows, columns=COLUMNS)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").astype("Int64")
    for col in ["user", "status", "method", "path", "user_agent"]:
        df[col] = df[col].fillna("")
    return df.sort_values("timestamp").reset_index(drop=True)
