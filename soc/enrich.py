"""Threat-intel enrichment: look up an IP's reputation on AbuseIPDB (optional)."""
import ipaddress

import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def abuseipdb_check(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    """Return {'ok': True, ...data} or {'ok': False, 'error': msg}."""
    if not is_public_ip(ip):
        return {"ok": False, "error": "Private or reserved IP: nothing to look up on the internet."}
    if not api_key:
        return {"ok": False, "error": "No AbuseIPDB API key set."}
    try:
        r = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=10,
        )
        if r.status_code != 200:
            return {"ok": False, "error": f"AbuseIPDB returned HTTP {r.status_code}: {r.text[:150]}"}
        return {"ok": True, **r.json().get("data", {})}
    except requests.RequestException as e:
        return {"ok": False, "error": f"Network error: {e}"}
