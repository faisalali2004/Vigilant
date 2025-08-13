from urllib.parse import urlparse, urlunparse

def normalize_base(url: str) -> str:
    if not url.startswith(("http://","https://")):
        url = "http://" + url
    parsed = urlparse(url)
    cleaned_path = parsed.path if parsed.path != "/" else ""
    return urlunparse((parsed.scheme, parsed.netloc, cleaned_path, "", "", ""))

def is_same_domain(base, url):
    pb = urlparse(base)
    pu = urlparse(url)
    return (pb.scheme, pb.netloc) == (pu.scheme, pu.netloc)

def strip_fragment(url):
    from urllib.parse import urlparse, urlunparse
    p = urlparse(url)
    return urlunparse(p._replace(fragment=""))
