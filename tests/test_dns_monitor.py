from dns_monitor import (
    resolve_hostname,
    query_dns_server
)


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


def test_dns_server_result_structure():
    result = query_dns_server(
        "8.8.8.8",
        "google.com"
    )

    assert "dns_server" in result
    assert "hostname" in result
    assert "status" in result
    assert "resolved" in result
    assert "ip_address" in result
    assert "response_time_ms" in result


def test_dns_server_result_types():
    result = query_dns_server(
        "8.8.8.8",
        "google.com"
    )

    assert result["dns_server"] == "8.8.8.8"
    assert result["hostname"] == "google.com"

    assert result["status"] in (
        "NOERROR",
        "NXDOMAIN",
        "SERVFAIL",
        "TIMEOUT",
        "ERROR"
    )

    assert isinstance(result["resolved"], bool)

    if result["resolved"]:
        assert result["ip_address"] is not None
        assert result["response_time_ms"] is not None


def test_invalid_dns_server():
    result = query_dns_server(
        "192.0.2.1",
        "google.com"
    )

    assert result["dns_server"] == "192.0.2.1"
    assert result["hostname"] == "google.com"
    assert result["status"] in (
        "TIMEOUT",
        "SERVFAIL",
        "ERROR"
    )
    assert result["resolved"] is False
    assert result["ip_address"] is None


def test_invalid_dns_server_format():
    result = query_dns_server(
        "not-a-dns-server",
        "google.com"
    )

    assert result["status"] == "ERROR"
    assert result["resolved"] is False
    assert result["ip_address"] is None
