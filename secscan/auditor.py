import socket
import ssl
import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List

HEADER_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "name": "HSTS",
        "weight": 20,
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
    },
    {
        "header": "Content-Security-Policy",
        "name": "CSP",
        "weight": 20,
        "recommendation": "Define a Content-Security-Policy to mitigate XSS and data injection attacks"
    },
    {
        "header": "X-Frame-Options",
        "name": "X-Frame-Options",
        "weight": 15,
        "recommendation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent clickjacking"
    },
    {
        "header": "X-Content-Type-Options",
        "name": "X-Content-Type-Options",
        "weight": 15,
        "recommendation": "Set X-Content-Type-Options to 'nosniff'"
    },
    {
        "header": "Referrer-Policy",
        "name": "Referrer-Policy",
        "weight": 10,
        "recommendation": "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'"
    },
    {
        "header": "Permissions-Policy",
        "name": "Permissions-Policy",
        "weight": 10,
        "recommendation": "Specify Permissions-Policy to control browser features (camera, microphone, geolocation)"
    }
]

def calculate_grade(score: int) -> str:
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 50:
        return "D"
    return "F"

def audit_ssl(hostname: str, port: int = 443) -> Dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=4.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Expiry check
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.datetime.utcnow()).days
                else:
                    days_left = 0

                issuer = dict(x[0] for x in cert.get("issuer", []))
                issuer_name = issuer.get("organizationName") or issuer.get("commonName") or "Unknown CA"

                is_valid = days_left > 0
                return {
                    "valid": is_valid,
                    "days_remaining": days_left,
                    "issuer": issuer_name,
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "status": "PASS" if is_valid and days_left > 14 else ("WARN" if is_valid else "FAIL"),
                    "recommendation": f"Valid for {days_left} days ({issuer_name})" if is_valid else "Certificate expired or invalid"
                }
    except Exception as e:
        return {
            "valid": False,
            "days_remaining": 0,
            "issuer": "None",
            "tls_version": "None",
            "cipher": "None",
            "status": "FAIL",
            "recommendation": f"SSL connection failed: {str(e)[:45]}"
        }

def evaluate_headers(response_headers: Dict[str, str]) -> List[Dict[str, Any]]:
    # Normalize headers to lowercase
    normalized = {k.lower(): v for k, v in response_headers.items()}
    results = []

    for check in HEADER_CHECKS:
        hdr = check["header"].lower()
        if hdr in normalized:
            val = normalized[hdr]
            results.append({
                "category": check["header"],
                "status": "PASS",
                "points": check["weight"],
                "value": val[:40] + ("..." if len(val) > 40 else ""),
                "recommendation": "Optimal configuration detected"
            })
        else:
            results.append({
                "category": check["header"],
                "status": "FAIL",
                "points": 0,
                "value": "Missing",
                "recommendation": check["recommendation"]
            })

    return results

def compute_audit_summary(target: str, header_results: List[Dict[str, Any]], ssl_info: Dict[str, Any]) -> Dict[str, Any]:
    earned_points = sum(r["points"] for r in header_results)
    ssl_points = 20 if ssl_info["status"] == "PASS" else (10 if ssl_info["status"] == "WARN" else 0)
    
    total_score = min(100, int((earned_points + ssl_points) / 110 * 100))
    grade = calculate_grade(total_score)

    return {
        "target": target,
        "score": total_score,
        "grade": grade,
        "headers": header_results,
        "ssl": ssl_info
    }
