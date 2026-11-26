"""
Detection rules.

Each rule looks at the parsed events and returns alerts. Rules are mapped to
MITRE ATT&CK techniques so analysts know what kind of behaviour they see.
"""
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote_plus

import pandas as pd

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
ALERT_COLUMNS = ["timestamp", "severity", "rule", "src_ip", "count", "description", "mitre"]

WEB_ATTACK_PATTERNS = {
    "SQL Injection": re.compile(
        r"(\bunion\b.+\bselect\b|'\s*or\s*'[^']*'\s*=\s*'|\bor\b\s+\d+\s*=\s*\d+|\band\b\s+\d+\s*=\s*\d+"
        r"|\bsleep\s*\(|\bbenchmark\s*\(|\bdrop\s+table\b|information_schema|;\s*--|'\s*--)", re.I),
    "Cross-Site Scripting (XSS)": re.compile(
        r"(<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*svg|<\s*iframe|alert\s*\()", re.I),
    "Path Traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)", re.I),
    "Command Injection": re.compile(
        r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping)\b", re.I),
}

SCANNER_UAS = ["sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "dirb",
               "wpscan", "nuclei", "zgrab", "hydra", "ffuf", "acunetix", "nessus"]


@dataclass
class Thresholds:
    brute_force_attempts: int = 5       # failed logins ...
    brute_force_window_min: int = 5     # ... within N minutes
    port_scan_ports: int = 10           # distinct ports ...
    port_scan_window_sec: int = 60      # ... within N seconds
    dir_brute_errors: int = 20          # 4xx responses ...
    dir_brute_window_sec: int = 60      # ... within N seconds


def _bursts(times: list, window: pd.Timedelta, threshold: int, keys: list | None = None):
    """
    Find non-overlapping bursts where at least `threshold` events (or distinct
    `keys`, e.g. ports) fall inside a sliding `window`.
    Returns [(start, end, n_events, n_distinct)].
    """
    out, i, n = [], 0, len(times)
    while i < n:
        j = i
        while j + 1 < n and times[j + 1] - times[i] <= window:
            j += 1
        size = len(set(keys[i:j + 1])) if keys is not None else j - i + 1
        if size >= threshold:
            k = j  # keep extending while activity continues
            while k + 1 < n and times[k + 1] - times[k] <= window:
                k += 1
            distinct = len(set(keys[i:k + 1])) if keys is not None else k - i + 1
            out.append((times[i], times[k], k - i + 1, distinct))
            i = k + 1
        else:
            i += 1
    return out


def _fmt_dur(start, end) -> str:
    sec = int((end - start).total_seconds())
    return f"{sec}s" if sec < 120 else f"{sec // 60} min"


def detect_brute_force(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    alerts = []
    failed = df[df["event"] == "failed_login"]
    success = df[df["event"] == "successful_login"]
    window = pd.Timedelta(minutes=th.brute_force_window_min)
    for ip, grp in failed.groupby("src_ip"):
        times = list(grp["timestamp"])
        for start, end, count, _ in _bursts(times, window, th.brute_force_attempts):
            users = grp[(grp["timestamp"] >= start) & (grp["timestamp"] <= end)]["user"]
            top_users = ", ".join(users.value_counts().head(3).index)
            alerts.append({
                "timestamp": start, "severity": "High", "rule": "SSH Brute Force", "src_ip": ip,
                "count": count, "mitre": "T1110 Brute Force",
                "description": f"{count} failed SSH logins in {_fmt_dur(start, end)} (users tried: {top_users})",
            })
            after = success[(success["src_ip"] == ip) & (success["timestamp"] >= start)
                            & (success["timestamp"] <= end + pd.Timedelta(hours=1))]
            if not after.empty:
                hit = after.iloc[0]
                alerts.append({
                    "timestamp": hit["timestamp"], "severity": "Critical",
                    "rule": "Possible Account Compromise", "src_ip": ip, "count": 1,
                    "mitre": "T1078 Valid Accounts",
                    "description": f"Successful login as '{hit['user']}' right after {count} failed attempts",
                })
    return alerts


def detect_port_scan(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    alerts = []
    fw = df[(df["source"] == "Firewall") & df["dst_port"].notna()]
    window = pd.Timedelta(seconds=th.port_scan_window_sec)
    for ip, grp in fw.groupby("src_ip"):
        times, ports = list(grp["timestamp"]), list(grp["dst_port"])
        for start, end, count, distinct in _bursts(times, window, th.port_scan_ports, keys=ports):
            sev = "High" if distinct >= 100 else "Medium"
            alerts.append({
                "timestamp": start, "severity": sev, "rule": "Port Scan", "src_ip": ip, "count": count,
                "mitre": "T1046 Network Service Discovery",
                "description": f"{distinct} different ports probed in {_fmt_dur(start, end)}",
            })
    return alerts


def detect_web_attacks(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    web = df[df["source"] == "Web"]
    hits = []
    for ts, ip, path in zip(web["timestamp"], web["src_ip"], web["path"]):
        decoded = unquote_plus(unquote_plus(path))
        for attack, pattern in WEB_ATTACK_PATTERNS.items():
            if pattern.search(decoded):
                hits.append((ts, ip, attack, decoded))
    alerts = []
    if not hits:
        return alerts
    h = pd.DataFrame(hits, columns=["timestamp", "src_ip", "attack", "path"])
    for (ip, attack), grp in h.groupby(["src_ip", "attack"]):
        sample = grp["path"].iloc[0]
        alerts.append({
            "timestamp": grp["timestamp"].min(), "severity": "High", "rule": attack, "src_ip": ip,
            "count": len(grp), "mitre": "T1190 Exploit Public-Facing Application",
            "description": f"{len(grp)} malicious request(s), e.g. {sample[:90]}",
        })
    return alerts


def detect_scanner_tools(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    web = df[df["source"] == "Web"]
    alerts = []
    for ip, grp in web.groupby("src_ip"):
        ua_lower = grp["user_agent"].str.lower()
        for tool in SCANNER_UAS:
            mask = ua_lower.str.contains(tool, regex=False)
            if mask.any():
                alerts.append({
                    "timestamp": grp.loc[mask, "timestamp"].min(), "severity": "Medium",
                    "rule": "Hacking Tool Detected", "src_ip": ip, "count": int(mask.sum()),
                    "mitre": "T1595 Active Scanning",
                    "description": f"User-Agent shows '{tool}' ({int(mask.sum())} requests)",
                })
                break
    return alerts


def detect_dir_bruteforce(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    web = df[(df["source"] == "Web") & df["status"].isin(["400", "401", "403", "404"])]
    window = pd.Timedelta(seconds=th.dir_brute_window_sec)
    alerts = []
    for ip, grp in web.groupby("src_ip"):
        for start, end, count, _ in _bursts(list(grp["timestamp"]), window, th.dir_brute_errors):
            alerts.append({
                "timestamp": start, "severity": "Medium", "rule": "Directory Brute Force", "src_ip": ip,
                "count": count, "mitre": "T1595.003 Wordlist Scanning",
                "description": f"{count} error responses (4xx) in {_fmt_dur(start, end)}, likely guessing hidden pages",
            })
    return alerts


RULES = [detect_brute_force, detect_port_scan, detect_web_attacks, detect_scanner_tools, detect_dir_bruteforce]


def run_all(df: pd.DataFrame, th: Thresholds | None = None) -> pd.DataFrame:
    th = th or Thresholds()
    if df.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    alerts = [a for rule in RULES for a in rule(df, th)]
    out = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
    if out.empty:
        return out
    out["severity"] = pd.Categorical(out["severity"], categories=SEVERITY_ORDER, ordered=True)
    return out.sort_values(["severity", "timestamp"], ascending=[True, False]).reset_index(drop=True)


def ip_risk_table(alerts: pd.DataFrame) -> pd.DataFrame:
    """Rank attacker IPs by a simple risk score (Critical=10, High=5, Medium=2, Low=1)."""
    if alerts.empty:
        return pd.DataFrame(columns=["src_ip", "alerts", "risk_score", "rules"])
    weights = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
    a = alerts.assign(w=alerts["severity"].astype(str).map(weights))
    return (a.groupby("src_ip")
             .agg(alerts=("rule", "size"), risk_score=("w", "sum"),
                  rules=("rule", lambda r: ", ".join(sorted(set(r)))))
             .reset_index().sort_values("risk_score", ascending=False))
