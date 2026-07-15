import time
import httpx
from huginn.core.collector import Collector
from huginn.core.models import Finding

class WaybackError(Exception):
    """Error to consulte wayback machine, after retries"""

class WaybackCollector(Collector):
    name = "wayback"
    BASE_URL = "https://web.archive.org/cdx/search/cdx"
    MAX_RETRIES = 3
    BACKOFF_SECONDS = 2

    def collect(self, target: str) -> list[Finding]:
        rows = self._fetch(target)
        return self._parse(rows)
    
    def _fetch(self, target: str) -> list[list[str]]:
        last_error = None

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                resp = httpx.get(
                    self.BASE_URL,
                    params={
                        "url": f"{target}/*",
                        "output": "json",
                        "fl": "original",
                        "limit": 100,
                    },
                    timeout=30,
                )
                resp.raise_for_status()
                return resp.json()
            
            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_error = exc
                if attempt < self.MAX_RETRIES:
                    time.sleep(self.BACKOFF_SECONDS * attempt)

        raise WaybackError(
            f"Wayback Machine unavailable after {self.MAX_RETRIES} attempts: {last_error}"
        ) from last_error
    
    def _parse(self, rows: list[list[str]]) -> list[Finding]:
        if not rows:
            return []
        
        urls = {row[0] for row in rows[1:]}

        return [
            Finding(kind="wayback_url", value=url, source=self.name)
            for url in sorted(urls)
        ]