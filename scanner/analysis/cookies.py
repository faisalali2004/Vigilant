def analyze_cookies(cookies, url):
    findings = []
    for c in cookies:
        name = getattr(c, "name", str(c))
        secure = getattr(c, "secure", False)
        httponly = getattr(c, "has_nonstandard_attr", lambda _: False)("httponly") or getattr(c, "rest", {}).get("HttpOnly", False)
        issues = []
        severity = "Info"
        if "sess" in name.lower() or "auth" in name.lower() or "token" in name.lower():
            if not secure:
                issues.append("Missing Secure flag on likely session cookie")
                severity = "Medium"
            if not httponly:
                issues.append("Missing HttpOnly flag on likely session cookie")
                severity = "Medium"
        else:
            if not secure:
                issues.append("Missing Secure flag")
            if not httponly:
                issues.append("Missing HttpOnly flag")
        if issues:
            findings.append({
                "id": None,
                "title": f"Insecure Cookie: {name}",
                "category": "Cookie",
                "severity": severity,
                "location": url,
                "description": "Cookie flags incomplete: " + "; ".join(issues),
                "evidence": f"Cookie={name}",
                "recommendation": "Set Secure and HttpOnly (and SameSite) on sensitive cookies."
            })
    return findings
