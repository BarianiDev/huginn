from huginn.collectors.tech import TechCollector


def test_parse_detects_known_signatures():
    haystack = "server: nginx\n<link href='https://site.com/wp-content/themes/x.css'>"
    findings = TechCollector()._parse(haystack)
    values = {f.value for f in findings}

    assert values == {"Nginx", "WordPress"}
    assert all(f.kind == "technology" for f in findings)
    assert all(f.source == "tech" for f in findings)


def test_parse_no_matches_returns_empty_list():
    assert TechCollector()._parse("") == []