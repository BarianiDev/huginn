from huginn.collectors.wayback import WaybackCollector


def test_parse_dedups_and_skips_header_row():
    rows = [
        ["original"],
        ["http://example.com/"],
        ["http://example.com/page1"],
        ["http://example.com/"],
    ]

    findings = WaybackCollector()._parse(rows)
    values = [f.value for f in findings]

    assert values == ["http://example.com/", "http://example.com/page1"]
    assert all(f.kind == "wayback_url" for f in findings)
    assert all(f.source == "wayback" for f in findings)


def test_parse_empty_rows_returns_empty_list():
    assert WaybackCollector()._parse([]) == []