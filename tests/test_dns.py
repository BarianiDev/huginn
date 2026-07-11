from huginn.collectors.dns import DnsCollector

def test_parse_builds_findings_with_record_type_metadata():
    answers = ["1.2.3.4", "5.6.7.8"]
    findings = DnsCollector()._parse(answers, "A")

    values = [f.value for f in findings]

    assert values == ["1.2.3.4", "5.6.7.8"]
    assert all(f.kind == "dns_record" for f in findings)
    assert all(f.source == "dns" for f in findings)
    assert all(f.metadata == {"record_type": "A"} for f in findings)

def test_parse_empty_answers_returns_empty_list():
    assert DnsCollector()._parse([], "TXT") == []