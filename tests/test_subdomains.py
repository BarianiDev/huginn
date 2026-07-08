from huginn.collectors.subdomains import CrtShCollector

def test_parse_dedup_wildcard_filter():
    entries = [
        {"name_value": "mail.example.com\n*.example.com"},
        {"name_value": "mail.example.com"},
        {"name_value": "evil.notexample.com"},
        {"name_value": "example.com"},
    ]

    findings  = CrtShCollector()._parse(entries, "example.com")
    values = [f.value for f in findings]

    assert values == ["example.com", "mail.example.com"]
    assert all(f.kind == "subdomain" for f in findings)
    assert all(f.source == "crtsh" for f in findings)