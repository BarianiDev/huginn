from huginn.collectors.whois import WhoisCollector


def test_parse_extracts_known_fields():
    record = {
        "registrar": "Example Registrar",
        "creation_date": "1995-08-14",
        "expiration_date": "2026-08-13",
        "updated_date": None,
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "emails": None,
        "status": None,
    }

    findings = WhoisCollector()._parse(record)
    values = {(f.value, f.metadata["field"]) for f in findings}

    assert values == {
        ("Example Registrar", "registrar"),
        ("1995-08-14", "creation_date"),
        ("2026-08-13", "expiration_date"),
        ("ns1.example.com", "name_servers"),
        ("ns2.example.com", "name_servers"),
    }
    assert all(f.kind == "whois" for f in findings)
    assert all(f.source == "whois" for f in findings)


def test_parse_skips_falsy_fields():
    record = {field: None for field in WhoisCollector.FIELDS}
    assert WhoisCollector()._parse(record) == []