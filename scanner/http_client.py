import time
import requests

class HttpClient:
    def __init__(self, timeout, user_agent, delay, logger):
        self.timeout = timeout
        self.user_agent = user_agent
        self.delay = delay
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def get(self, url, allow_redirects=True):
        self.logger.debug(f"GET {url}")
        if self.delay:
            time.sleep(self.delay)
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=allow_redirects)
            return resp
        except requests.RequestException as e:
            self.logger.debug(f"Request error {url}: {e}")
            return None

    def post(self, url, data):
        self.logger.debug(f"POST {url} data={data}")
        if self.delay:
            time.sleep(self.delay)
        try:
            resp = self.session.post(url, data=data, timeout=self.timeout)
            return resp
        except requests.RequestException as e:
            self.logger.debug(f"Request error {url}: {e}")
            return None
