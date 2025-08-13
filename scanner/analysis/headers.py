def analyze_security_headers(headers, target):
    findings = []
    # Normalize keys to case-insensitive access
    norm = {k.lower(): v for k, v in headers.items()}
    https = target.startswith("https://")

    def add(title, severity, desc, evidence, rec):
        findings.append({
            "id": None,
            "title": title,
            "category": "Headers",
            "severity": severity,
            "location": target,
            "description": desc,
            "evidence": evidence[:300],
            "recommendation": rec
        })

    if "content-security-policy" not in norm:
        add("Missing Content-Security-Policy",
            "Medium",
            "CSP header not found; this increases risk of XSS.",
            "No Content-Security-Policy header",
            "Define a restrictive CSP to mitigate script injection.")
    if https and "strict-transport-security" not in norm:
        add("Missing Strict-Transport-Security",
            "Medium",
            "HSTS header not set; browsers may allow protocol downgrades.",
            "No Strict-Transport-Security header",
            "Add HSTS with a suitable max-age and includeSubDomains.")
    if "x-frame-options" not in norm:
        add("Missing X-Frame-Options",
            "Low",
            "Clickjacking protection header not present.",
            "No X-Frame-Options header",
            "Add X-Frame-Options: DENY or use CSP frame-ancestors.")
    if "x-content-type-options" not in norm:
        add("Missing X-Content-Type-Options",
            "Low",
            "MIME sniffing not disabled; potential content-type confusion.",
            "No X-Content-Type-Options header",
            "Add X-Content-Type-Options: nosniff.")
    if "referrer-policy" not in norm:
        add("Missing Referrer-Policy",
            "Low",
            "Referrer-Policy not set; may leak URL info in Referer header.",
            "No Referrer-Policy header",
            "Add a strict Referrer-Policy (e.g., no-referrer or same-origin).")
    if "permissions-policy" not in norm:
        add("Missing Permissions-Policy",
            "Info",
            "No Permissions-Policy; modern feature usage not limited.",
            "No Permissions-Policy header",
            "Add Permissions-Policy limiting powerful features.")
    return findings
