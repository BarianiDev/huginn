import whois
from huginn.core.collector import Collector
from huginn.core.models import Finding


class WhoisError(Exception):
    """Error consulting whois data."""

class WhoisCollector(Collector):
    name = "whois"
    FIELDS = [
        "registrar",
        "creation_date",
        "expiration_date",
        "updated_date",
        "name_servers",
        "emails",
        "status",
    ]

    def collect(self, target: str) -> list[Finding]:
        record = self._fetch(target)
        return self._parse(record)
    
    def _fetch(self, target: str) -> dict:
        try:
            record = whois.whois(target)
        except Exception as exc:
            raise WhoisError(f"WHOIS lookup failed for {target}: {exc}") from exc
        
        if not record.get("domain_name"):
            raise WhoisError(f"No WHOIS data found for {target}")
        
        return record
    
    def _parse(self, record: dict) -> list[Finding]:
        findings = []

        for field in self.FIELDS:
            value = record.get(field)
            if not value:
                continue


            values = value if isinstance(value, list) else [value]
            for item in values:
                findings.append(
                    Finding(
                        kind="whois",
                        value=str(item),
                        source=self.name,
                        metadata={"field": field}
                    )
                )

        return findings
