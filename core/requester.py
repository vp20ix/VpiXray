import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 10
DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) VpiXray/0.1"

class Requester:
    def __init__(self, timeout=DEFAULT_TIMEOUT, headers=None, proxy=None, verify=False, cookie=None):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_UA})
        if headers:
            self.session.headers.update(headers)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if cookie:
            for item in cookie.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())
        retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        self.session.mount("http://", HTTPAdapter(max_retries=retries))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
        self.verify = verify

    def get(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", False)
        try:
            return self.session.get(url, **kwargs)
        except requests.RequestException:
            return None

    def post(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", False)
        try:
            return self.session.post(url, **kwargs)
        except requests.RequestException:
            return None
