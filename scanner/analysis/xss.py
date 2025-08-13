import re
import urllib.parse
from ..utils.html import is_raw_reflection

def test_reflected_xss(client, pages, forms):
    token_base = "xss_probe_"
    import secrets
    token = token_base + secrets.token_hex(4)
    findings = []

    tested_urls = set()
    for url in pages.keys():
        if "?" in url:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            for param in qs.keys():
                new_qs = qs.copy()
                new_qs[param] = [token]
                new_query = urllib.parse.urlencode({k: v[0] for k,v in new_qs.items()})
                new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                if new_url in tested_urls:
                    continue
                resp = client.get(new_url)
                tested_urls.add(new_url)
                if resp and resp.status_code == 200 and token in resp.text:
                    if is_raw_reflection(resp.text, token):
                        findings.append({
                            "id": None,
                            "title": "Potential Reflected XSS",
                            "category": "XSS",
                            "severity": "Medium",
                            "location": new_url,
                            "description": "Token reflected unencoded in response.",
                            "evidence": f"...{token}...",
                            "recommendation": "HTML-encode user-supplied input and implement a CSP."
                        })
                    else:
                        findings.append({
                            "id": None,
                            "title": "Parameter Reflection (Encoded)",
                            "category": "XSS",
                            "severity": "Info",
                            "location": new_url,
                            "description": "Token reflected but appears HTML-encoded.",
                            "evidence": f"...{token}...",
                            "recommendation": "Continue encoding and validate/escape inputs."
                        })

    for form in forms:
        if form["method"] == "get":
            continue
        data = {}
        changed = False
        for inp in form["inputs"]:
            if inp["name"] and inp["type"] in ("text", "search", "email", "password", "textarea"):
                data[inp["name"]] = token
                changed = True
        if not changed:
            continue
        resp = client.post(form["action"], data=data)
        if resp and resp.status_code == 200 and token in resp.text:
            if is_raw_reflection(resp.text, token):
                findings.append({
                    "id": None,
                    "title": "Potential Reflected XSS (Form)",
                    "category": "XSS",
                    "severity": "Medium",
                    "location": form["action"],
                    "description": "Form input reflected unencoded in response.",
                    "evidence": f"...{token}...",
                    "recommendation": "HTML-encode user-supplied input and implement a CSP."
                })
            else:
                findings.append({
                    "id": None,
                    "title": "Form Input Reflection (Encoded)",
                    "category": "XSS",
                    "severity": "Info",
                    "location": form["action"],
                    "description": "Token reflected but appears HTML-encoded.",
                    "evidence": f"...{token}...",
                    "recommendation": "Maintain proper output encoding."
                })
    return findings
