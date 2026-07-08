import dns.resolver
from huginn.core.collector import Collector
from huginn.core.models import Finding


class DnsCollector(Collector):
    name = "dns"
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]

    def collect(self, target: str) -> list[Finding]:
        findings = []
        for record_type in self.RECORD_TYPES:
            answers = self._fetch(target, record_type)
            findings.extend(self._parse(answers, record_type))
        return findings
    
    def _fetch(self, target: str, record_type: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(target, record_type)
            return [answer.to_text() for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        
    def _parse(self, answers: list[str], record_type: str) -> list[Finding]:
        return [
            Finding(
                kind="dns_record",
                value=answer,
                source=self.name,
                metadata={"record_type": record_type},
            )
            for answer in answers
        ]
        