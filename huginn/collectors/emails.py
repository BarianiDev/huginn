import re
import httpx
from huginn.core.collector import Collector
from huginn.core.models import Finding

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

class EmailCollector(Collector):
    name = "emails"

    def collect(self, target: str) -> list[Finding]:
        html = self._fetch(target)
        return self._parse(html, target)
    
    def _fetch(self, target: str) -> str:
        try:
            resp = httpx.get(f"https://{target}", timeout=10, follow_redirects=True)
            resp.raise_for_status()
            return resp.text
        except (httpx.HTTPStatusError, httpx.RequestError):
            return ""
        
    def _parse(self, html: str, target: str) -> list[Finding]:
        emails = {
            match.lower()
                for match in EMAIL_PATTERN.findall(html)
                if match.lower().endswith("@" + target) or match.lower().endswith("." + target)
             }
        
        return [
            Finding(kind="email", value=email, source=self.name)
            for email in sorted(emails)
        ]