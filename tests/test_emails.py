from huginn.collectors.emails import EmailCollector


def test_parse_filters_to_target_domain():
    html = """
        <p>contact us: sales@example.com or support@mail.example.com</p>
        <p>unrelated: help@otherwidget.com</p>
    """

    findings = EmailCollector()._parse(html, "example.com")
    values = [f.value for f in findings]

    assert values == ["sales@example.com", "support@mail.example.com"]
    assert all(f.kind == "email" for f in findings)
    assert all(f.source == "emails" for f in findings)


def test_parse_no_matches_returns_empty_list():
    assert EmailCollector()._parse("<p>no contact info here</p>", "example.com") == []