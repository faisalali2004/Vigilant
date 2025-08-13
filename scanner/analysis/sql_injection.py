import urllib.parse
import re

SQL_ERRORS = re.compile(
    r"(You have an error in your SQL syntax|Warning: mysql_|pg_query\(|SQLSTATE\[HY000\]|Microsoft OLE DB Provider|ODBC SQL Server Driver|SQLite/JDBCDriver|ORA-\d+)",
    re.IGNORECASE
)

def test_basic_sqli(client, pages, forms):
    findings = []
    test_payloads = ["'", '"']
    tested = set()

    for url in pages.keys():
        if "?" not in url:
            continue
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for param in qs:
            for payload in test_payloads:
                new_qs = {k: v[0] for k,v in qs.items()}
                new_qs[param] = new_qs[param] + payload
                new_query = urllib.parse.urlencode(new_qs)
                new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                if new_url in tested:
                    continue
                resp = client.get(new_url)
                tested.add(new_url)
                if resp and resp.status_code == 200 and SQL_ERRORS.search(resp.text or ""):
                    findings.append({
                        "id": None,
                        "title": "Possible SQL Injection Indicator",
                        "category": "SQLi",
                        "severity": "Medium",
                        "location": new_url,
                        "description": "Database error message observed after payload injection.",
                        "evidence": SQL_ERRORS.search(resp.text).group(0)[:100],
                        "recommendation": "Use parameterized queries, sanitize inputs, suppress verbose DB errors."
                    })
    for form in forms:
        if form["method"] != "post":
            continue
        for inp in form["inputs"]:
            if not inp["name"]:
                continue
            for payload in test_payloads:
                data = {}
                for j in form["inputs"]:
                    if j["name"]:
                        data[j["name"]] = "test"
                data[inp["name"]] = "test" + payload
                resp = client.post(form["action"], data=data)
                if resp and resp.status_code == 200 and SQL_ERRORS.search(resp.text or ""):
                    findings.append({
                        "id": None,
                        "title": "Possible SQL Injection Indicator (Form)",
                        "category": "SQLi",
                        "severity": "Medium",
                        "location": form["action"],
                        "description": "Database error message observed after form field payload injection.",
                        "evidence": SQL_ERRORS.search(resp.text).group(0)[:100],
                        "recommendation": "Use parameterized queries, sanitize inputs, suppress verbose DB errors."
                    })
    return findings
