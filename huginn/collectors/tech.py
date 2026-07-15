import httpx
from huginn.core.collector import Collector
from huginn.core.models import Finding

SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Shopify": ["cdn.shopify.com", "shopify"],
    "Wix": ["wix.com", "wixstatic.com"],
    "Cloudflare": ["cloudflare"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "React": ["react-dom", "__reactcontainer"],
    "jQuery": ["jquery"],
    "Google Analytics": ["google-analytics.com", "gtag("],
}

class TechCollector(Collector):
    name = "tech"

    def collect(self, target: str) -> list[Finding]:
        haystack = self._fetch(target)
        return self._parse(haystack)
    
    def _fetch(self, target: str) -> str:
        try:
            resp = httpx.get(f"https://{target}", timeout=10, follow_redirects=True)
        except httpx.RequestError:
            return ""
        
        headers_text = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
        return f"{headers_text}\n{resp.text}".lower()
    
    def _parse(self, haystack: str) -> list[Finding]:
        return [
            Finding(kind="technology", value=tech, source=self.name)
            for tech, keywords in SIGNATURES.items()
            if any(keyword in haystack for keyword in keywords)
        ]