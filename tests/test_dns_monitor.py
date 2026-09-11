from dns_monitor import resolve_hostname


def test_resolve_hostname():
    result = resolve_hostname("google.com")

    assert result["hostname"] == "google.com"
    assert result["resolved"] is True
    assert result["ip_address"] is not None


def test_invalid_hostname():
    result = resolve_hostname(
        "this-domain-does-not-exist-12345.example"
    )

    assert result["resolved"] is False
    assert result["ip_address"] is None

