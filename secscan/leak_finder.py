"""
SecScan-CLI — Leak Finder (Phase 3)
Asynchronously probes a list of sensitive paths on the target host to detect
accidentally exposed files and secrets.
"""

import asyncio
import httpx
from typing import List, Dict, Any

# Dictionary of sensitive paths to probe
SENSITIVE_PATHS: List[Dict[str, str]] = [
    {"path": "/.env",                    "label": ".env (Root)",              "severity": "CRITICAL"},
    {"path": "/.env.local",              "label": ".env.local",               "severity": "CRITICAL"},
    {"path": "/.env.production",         "label": ".env.production",          "severity": "CRITICAL"},
    {"path": "/.env.backup",             "label": ".env.backup",              "severity": "CRITICAL"},
    {"path": "/.git/HEAD",               "label": ".git/HEAD",                "severity": "HIGH"},
    {"path": "/.git/config",             "label": ".git/config",              "severity": "HIGH"},
    {"path": "/wp-config.php",           "label": "wp-config.php",            "severity": "CRITICAL"},
    {"path": "/wp-config.php.bak",       "label": "wp-config.php.bak",        "severity": "CRITICAL"},
    {"path": "/configuration.php.old",   "label": "configuration.php.old",    "severity": "HIGH"},
    {"path": "/phpinfo.php",             "label": "phpinfo.php",              "severity": "HIGH"},
    {"path": "/.DS_Store",               "label": ".DS_Store",                "severity": "MEDIUM"},
    {"path": "/crossdomain.xml",         "label": "crossdomain.xml",          "severity": "MEDIUM"},
    {"path": "/server-status",           "label": "Apache /server-status",    "severity": "HIGH"},
    {"path": "/.htaccess",               "label": ".htaccess",                "severity": "MEDIUM"},
    {"path": "/backup.zip",              "label": "backup.zip",               "severity": "HIGH"},
    {"path": "/dump.sql",                "label": "dump.sql",                 "severity": "CRITICAL"},
]

# Signatures that confirm the file content is genuinely exposed (not a custom 200 page)
CONTENT_SIGNATURES: Dict[str, List[str]] = {
    "/.env":                ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "DATABASE_URL=", "API_KEY="],
    "/.env.local":          ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY=", "DATABASE_URL="],
    "/.env.production":     ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="],
    "/.env.backup":         ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="],
    "/.git/HEAD":           ["ref: refs/heads/"],
    "/.git/config":         ["[core]", "[remote"],
    "/phpinfo.php":         ["PHP Version", "phpinfo()"],
    "/wp-config.php":       ["DB_NAME", "DB_PASSWORD", "table_prefix"],
    "/wp-config.php.bak":   ["DB_NAME", "DB_PASSWORD"],
    "/server-status":       ["Apache Server Status", "requests currently being processed"],
    "/dump.sql":            ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
}


async def _probe_path(
    client: httpx.AsyncClient,
    base_url: str,
    entry: Dict[str, str],
) -> Dict[str, Any]:
    """Probe a single path and return a structured result."""
    path = entry["path"]
    url = base_url.rstrip("/") + path
    result: Dict[str, Any] = {
        "path": path,
        "label": entry["label"],
        "severity": entry["severity"],
        "url": url,
        "status_code": None,
        "exposed": False,
        "detail": "Protected (not reachable)",
    }
    try:
        resp = await client.get(url, follow_redirects=False)
        result["status_code"] = resp.status_code

        if resp.status_code in (301, 302, 307, 308):
            result["detail"] = f"Redirect → {resp.headers.get('location', '?')}"
            return result

        if resp.status_code == 200:
            body = resp.text[:2048]  # read first 2 KB only
            signatures = CONTENT_SIGNATURES.get(path, [])
            if signatures:
                # Confirm exposure via content signatures
                if any(sig in body for sig in signatures):
                    result["exposed"] = True
                    result["detail"] = f"EXPOSED — content confirmed (HTTP 200)"
                else:
                    result["detail"] = "HTTP 200 but content mismatch (likely soft-404)"
            else:
                # No signature list: treat HTTP 200 as exposure
                result["exposed"] = True
                result["detail"] = "EXPOSED — HTTP 200 (no signature validation)"
        elif resp.status_code == 403:
            result["detail"] = "Forbidden (403) — path exists but access denied"
        elif resp.status_code == 404:
            result["detail"] = "Not Found (404)"
        else:
            result["detail"] = f"HTTP {resp.status_code}"

    except httpx.TimeoutException:
        result["detail"] = "Timeout"
    except Exception as exc:  # noqa: BLE001
        result["detail"] = f"Error: {str(exc)[:60]}"

    return result


async def _run_all(base_url: str, timeout: float = 6.0) -> List[Dict[str, Any]]:
    """Run all probes concurrently and return results."""
    headers = {"User-Agent": "SecScan-CLI/1.0 Security Auditor (+https://github.com/Clickdroit/SecScan-CLI)"}
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)

    async with httpx.AsyncClient(headers=headers, timeout=timeout, limits=limits, verify=False) as client:
        tasks = [_probe_path(client, base_url, entry) for entry in SENSITIVE_PATHS]
        return await asyncio.gather(*tasks)


def run_leak_finder(base_url: str, timeout: float = 6.0) -> List[Dict[str, Any]]:
    """
    Public synchronous entry point.

    Runs all path probes asynchronously and returns a sorted list of results,
    with exposed files first ordered by severity.
    """
    results = asyncio.run(_run_all(base_url, timeout))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda r: (not r["exposed"], severity_order.get(r["severity"], 99)))
    return results
