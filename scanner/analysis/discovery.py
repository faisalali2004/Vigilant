import re
def check_directory_listing(url, content):
    if not content:
        return None
    if re.search(r"<title>\s*Index of /", content, re.IGNORECASE) or "Index of /" in content:
        return {"url": url}
    return None

def probe_hidden_paths(client, base, wordlist):
    import urllib.parse
    results = []
    parts = urllib.parse.urlparse(base)
    root = f"{parts.scheme}://{parts.netloc}"
    for path in wordlist:
        candidate = root.rstrip("/") + "/" + path.strip("/")
        resp = client.get(candidate)
        status = resp.status_code if resp else None
        results.append({"url": candidate, "status": status})
    return results

def probe_exposed_files(client, base, files):
    import urllib.parse
    results = []
    parts = urllib.parse.urlparse(base)
    root = f"{parts.scheme}://{parts.netloc}"
    for f in files:
        candidate = root.rstrip("/") + "/" + f
        resp = client.get(candidate)
        status = resp.status_code if resp else None
        results.append({"url": candidate, "status": status, "path": f})
    return results
