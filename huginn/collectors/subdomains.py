import time
import httpx

from huginn.core.collector import Collector
from huginn.core.models import Finding


class CrtShError(Exception):
    """error consulting crt.sh even after retries."""

class CrtShCollector(Collector):
    name = "crtsh"
    BASE_URL = "https://crt.sh/"

    MAX_RETRIES = 3
    BACKOFF_SECONDS = 2

    def collect(self, target: str) -> list[Finding]:
        entries = self._fetch(target)
        return self._parse(entries, target)
    
    def _fetch(self, target: str) -> list[dict]:
       last_error: Exception | None = None

       for attempt in range(1, self.MAX_RETRIES +1):
           try:
               resp = httpx.get(
                   self.BASE_URL,
                   params={"q": f"%.{target}", "output": "json"},
                   timeout=30,
               )
               resp.raise_for_status()
               return resp.json()
           except (httpx.HTTPStatusError, httpx.RequestError) as exc:
               last_error = exc
               if attempt < self.MAX_RETRIES:
                   time.sleep(self.BACKOFF_SECONDS * attempt)
        
       raise CrtShError(
            f"crt.sh unvailable after {self.MAX_RETRIES} attempts: {last_error}"
        ) from last_error           




    def _parse(self, entries: list[dict], target: str) -> list[Finding]:
        hostnames: set[str] = set()

        for entry in entries:
            for host in entry.get("name_value", "").splitlines():
                host = host.strip().lower()
                if host.startswith("*."):
                    host = host[2:]
                if host == target or host.endswith("." + target):
                    hostnames.add(host)
        
        return [
            Finding(kind="subdomain", value=h, source=self.name)
            for h in sorted(hostnames)
        ]