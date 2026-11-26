"""
Sample log generator.

Creates realistic-looking SSH, web server and firewall logs that contain
normal activity plus several attack scenarios, so the dashboard can be
demoed without any real (private) data.

Attacker IPs come only from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so no real person's IP
is ever labelled as malicious.
"""
import random
from datetime import datetime, timedelta
from urllib.parse import quote

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/products?id=12",
    "/products?id=7", "/blog/post-1", "/blog/post-2", "/css/style.css",
    "/js/app.js", "/images/logo.png", "/login", "/search?q=laptop",
]
DIR_WORDLIST = [
    "/admin", "/wp-admin", "/wp-login.php", "/.env", "/.git/config", "/backup.zip",
    "/config.php", "/phpmyadmin", "/server-status", "/db.sql", "/old", "/test",
    "/api/v1/users", "/administrator", "/private", "/uploads", "/cgi-bin/", "/.htaccess",
]


def _syslog_ts(t: datetime) -> str:
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"


def _web_line(t, ip, path, status, ua, method="GET"):
    path = quote(path, safe="/?=&.-_")
    size = random.randint(200, 9000) if status < 400 else random.randint(150, 400)
    return f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0600] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def _ssh_failed(t, ip, user, invalid, rng):
    who = f"invalid user {user}" if invalid else user
    return (f"{_syslog_ts(t)} web01 sshd[{rng.randint(1000, 99999)}]: "
            f"Failed password for {who} from {ip} port {rng.randint(30000, 65000)} ssh2")


def _ssh_ok(t, ip, user, rng, method="password"):
    return (f"{_syslog_ts(t)} web01 sshd[{rng.randint(1000, 99999)}]: "
            f"Accepted {method} for {user} from {ip} port {rng.randint(30000, 65000)} ssh2")


def _fw_block(t, ip, port, rng):
    return (f"{_syslog_ts(t)} fw01 kernel: [{rng.uniform(1000, 99999):.6f}] [UFW BLOCK] IN=eth0 OUT= "
            f"SRC={ip} DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID={rng.randint(1, 65535)} "
            f"PROTO=TCP SPT={rng.randint(30000, 65000)} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0")


def generate(seed: int = 42, end: datetime | None = None, hours: int = 24) -> dict[str, str]:
    """Return {"auth.log": text, "access.log": text, "firewall.log": text}."""
    rng = random.Random(seed)
    random.seed(seed)
    end = (end or datetime.now()).replace(microsecond=0)
    start = end - timedelta(hours=hours)
    auth, web, fw = [], [], []

    def rand_time():
        return start + timedelta(seconds=rng.randint(0, hours * 3600 - 1))

    def at(hours_before):
        return end - timedelta(hours=hours_before)

    # ---------------- Normal activity ----------------
    staff = {"rizwan": "10.0.0.11", "deploy": "10.0.0.20", "backup": "10.0.0.25", "admin": "10.0.0.12"}
    for _ in range(45):
        user, ip = rng.choice(list(staff.items()))
        t = rand_time()
        if rng.random() < 0.15:  # typo, then success
            auth.append((t, _ssh_failed(t, ip, user, False, rng)))
            t += timedelta(seconds=rng.randint(5, 30))
        auth.append((t, _ssh_ok(t, ip, user, rng, rng.choice(["password", "publickey"]))))

    visitors = [f"172.16.{rng.randint(0, 20)}.{rng.randint(2, 254)}" for _ in range(70)]
    for _ in range(1600):
        ip, t = rng.choice(visitors), rand_time()
        path = rng.choice(NORMAL_PATHS)
        status = rng.choices([200, 304, 404], weights=[85, 12, 3])[0]
        if status == 404:
            path = "/favicon.ico"
        web.append((t, _web_line(t, ip, path, status, rng.choice(BROWSER_UAS))))

    for _ in range(120):  # background internet noise: single blocked probes
        t = rand_time()
        ip = f"100.64.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        fw.append((t, _fw_block(t, ip, rng.choice([23, 445, 3389, 5900, 8080]), rng)))

    # ---------------- Attack scenarios ----------------
    # A) SSH brute force that SUCCEEDS -> critical
    ip, t = "203.0.113.45", at(6)
    for _ in range(60):
        user = rng.choice(["root", "admin", "test", "oracle", "ubuntu", "pi", "guest", "user"])
        auth.append((t, _ssh_failed(t, ip, user, user not in ("root", "admin"), rng)))
        t += timedelta(seconds=rng.randint(1, 5))
    t += timedelta(minutes=4)
    auth.append((t, _ssh_ok(t, ip, "admin", rng)))

    # B) SSH brute force that fails
    ip, t = "198.51.100.23", at(14)
    for _ in range(25):
        auth.append((t, _ssh_failed(t, ip, "root", False, rng)))
        t += timedelta(seconds=rng.randint(10, 35))

    # C) Port scan
    ip, t = "192.0.2.77", at(9)
    ports = rng.sample(range(1, 10000), 110) + [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389]
    for port in ports:
        fw.append((t, _fw_block(t, ip, port, rng)))
        t += timedelta(milliseconds=rng.randint(100, 400))

    # D) SQL injection with sqlmap
    ip, t = "198.51.100.88", at(4)
    ua = "sqlmap/1.8.4#stable (https://sqlmap.org)"
    payloads = ["12' OR '1'='1", "12 UNION SELECT username,password FROM users--",
                "12; DROP TABLE users--", "12' AND SLEEP(5)--", "12 AND 1=1",
                "12' UNION SELECT NULL,table_name FROM information_schema.tables--"]
    for _ in range(40):
        web.append((t, _web_line(t, ip, f"/products?id={rng.choice(payloads)}", rng.choice([200, 500]), ua)))
        t += timedelta(seconds=rng.randint(1, 4))

    # E) Cross-site scripting attempts
    ip, t = "203.0.113.99", at(2)
    xss = ["<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>",
           "javascript:alert('xss')", "<svg onload=alert(1)>"]
    for _ in range(8):
        web.append((t, _web_line(t, ip, f"/search?q={rng.choice(xss)}", 200, BROWSER_UAS[2])))
        t += timedelta(seconds=rng.randint(10, 60))

    # F) Directory brute force with gobuster
    ip, t = "192.0.2.150", at(11)
    for i in range(300):
        path = DIR_WORDLIST[i % len(DIR_WORDLIST)] + ("" if i < len(DIR_WORDLIST) else f"{i}")
        status = 301 if path == "/admin" else 404
        web.append((t, _web_line(t, ip, path, status, "gobuster/3.6")))
        t += timedelta(milliseconds=rng.randint(200, 500))

    # G) Path traversal + command injection with Nikto
    ip, t = "198.51.100.200", at(1)
    ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:007634)"
    for path in ["/download?file=../../../../etc/passwd", "/download?file=..\\..\\windows\\win.ini",
                 "/ping?host=127.0.0.1;cat /etc/passwd", "/ping?host=8.8.8.8 && whoami",
                 "/download?file=../../../etc/shadow"]:
        web.append((t, _web_line(t, ip, path, rng.choice([400, 403, 200]), ua)))
        t += timedelta(seconds=rng.randint(2, 8))

    def render(rows):
        return "\n".join(line for _, line in sorted(rows, key=lambda r: r[0])) + "\n"

    return {"auth.log": render(auth), "access.log": render(web), "firewall.log": render(fw)}
