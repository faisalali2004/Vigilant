import re
import urllib.parse
from collections import deque
from bs4 import BeautifulSoup
from .utils.url import is_same_domain, strip_fragment
from .utils.logging import get_child_logger
from .utils.wordlists import HIDDEN_PATHS_SMALL, EXPOSED_FILES_SMALL

class Crawler:
    def __init__(self, client, base_url, max_pages, max_depth, logger, obey_robots=True):
        self.client = client
        self.base_url = base_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.logger = get_child_logger(logger, "crawler")
        self.pages = {}  # url-> metadata
        self.forms = []
        self.visited = set()
        self.queue = deque()
        self.obey_robots = obey_robots
        self.robots_rules = []
        self.hidden_wordlist = HIDDEN_PATHS_SMALL
        self.exposed_files_list = EXPOSED_FILES_SMALL

    def crawl(self):
        self._load_robots()
        self.queue.append((self.base_url, 0))
        while self.queue and len(self.pages) < self.max_pages:
            url, depth = self.queue.popleft()
            if depth > self.max_depth:
                continue
            norm = strip_fragment(url)
            if norm in self.visited:
                continue
            if self.obey_robots and self._disallowed(norm):
                self.logger.debug(f"Skipping disallowed by robots.txt: {norm}")
                continue
            self.visited.add(norm)
            resp = self.client.get(norm)
            if not resp:
                continue
            page_meta = {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "content": resp.text if "text" in resp.headers.get("Content-Type","") else "",
                "cookies": [c for c in resp.cookies],
                "url": norm
            }
            self.pages[norm] = page_meta
            if resp.status_code == 200 and page_meta["content"]:
                self._extract(norm, page_meta["content"], depth)

    def _extract(self, page_url, html, depth):
        soup = BeautifulSoup(html, "html.parser")
        # links
        for a in soup.find_all("a", href=True):
            href = urllib.parse.urljoin(page_url, a.get("href"))
            href = strip_fragment(href)
            if is_same_domain(self.base_url, href):
                if href not in self.visited and len(self.pages) + len(self.queue) < self.max_pages:
                    self.queue.append((href, depth+1))
        # forms
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").lower()
            action = form.get("action") or page_url
            action = urllib.parse.urljoin(page_url, action)
            inputs = []
            for inp in form.find_all(["input","textarea","select"]):
                name = inp.get("name")
                itype = inp.get("type","text")
                inputs.append({"name": name, "type": itype})
            self.forms.append({
                "page": page_url,
                "method": method,
                "action": action,
                "inputs": inputs
            })

    def _load_robots(self):
        if not self.obey_robots:
            return
        import urllib.parse
        parts = urllib.parse.urlparse(self.base_url)
        robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
        resp = self.client.get(robots_url)
        if not resp or resp.status_code != 200:
            return
        disallows = []
        for line in resp.text.splitlines():
            line=line.strip()
            if line.lower().startswith("disallow:"):
                rule = line.split(":",1)[1].strip()
                disallows.append(rule)
        self.robots_rules = disallows

    def _disallowed(self, url):
        # simple path matching
        import urllib.parse
        path = urllib.parse.urlparse(url).path
        for rule in self.robots_rules:
            if rule == "/":
                return True
            if rule and path.startswith(rule):
                return True
        return False
