from dataclasses import dataclass, field

@dataclass
class Finding:
    """A finding infos collect from a collector."""
    kind: str               # "subdomain", "dns_record", "email"...
    value: str              # the data, ex: "mail.example.com"
    source: str            # the source of the data, ex: "crt.sh"
    metadata: dict = field(default_factory=dict) # extras

@dataclass
class ScanResult:
    """Result of a scan, about a target."""
    target: str
    started_at: str
    findings: list[Finding] = field(default_factory=list)