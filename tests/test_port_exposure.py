from security.port_exposure import (
    analyze_service,
    analyze_services,
    classify_exposure,
    normalize_address
)


def test_ipv4_loopback_is_local():
    assert classify_exposure("127.0.0.1") == "LOCAL"


def test_ipv4_loopback_with_zone_is_local():
    assert classify_exposure("127.0.0.53%lo") == "LOCAL"


def test_ipv6_loopback_is_local():
    assert classify_exposure("::1") == "LOCAL"


def test_ipv4_wildcard_is_network():
    assert classify_exposure("0.0.0.0") == "NETWORK"


def test_ipv6_wildcard_is_network():
    assert classify_exposure("::") == "NETWORK"


def test_specific_ipv4_address():
    assert classify_exposure("192.168.1.83") == "SPECIFIC_INTERFACE"


def test_normalize_ipv6_zone_identifier():
    assert normalize_address("127.0.0.53%lo") == "127.0.0.53"


def test_normalize_ipv6_brackets():
    assert normalize_address("[::1]") == "::1"


def test_unknown_address():
    assert classify_exposure("not-an-ip-address") == "UNKNOWN"


def test_analyze_local_service():
    service = {
        "protocol": "TCP",
        "address": "127.0.0.53%lo",
        "port": 53
    }

    result = analyze_service(service)

    assert result["exposure"] == "LOCAL"
    assert result["severity"] == "INFO"


def test_analyze_network_service():
    service = {
        "protocol": "TCP",
        "address": "0.0.0.0",
        "port": 22
    }

    result = analyze_service(service)

    assert result["exposure"] == "NETWORK"
    assert result["severity"] == "WARNING"


def test_analyze_specific_interface_service():
    service = {
        "protocol": "TCP",
        "address": "192.168.1.83",
        "port": 8080
    }

    result = analyze_service(service)

    assert result["exposure"] == "SPECIFIC_INTERFACE"
    assert result["severity"] == "REVIEW"


def test_analyze_unknown_service():
    service = {
        "protocol": "TCP",
        "address": "not-an-ip",
        "port": 8080
    }

    result = analyze_service(service)

    assert result["exposure"] == "UNKNOWN"
    assert result["severity"] == "REVIEW"


def test_analyze_multiple_services():
    services = [
        {
            "protocol": "TCP",
            "address": "127.0.0.1",
            "port": 631
        },
        {
            "protocol": "TCP",
            "address": "0.0.0.0",
            "port": 22
        }
    ]

    results = analyze_services(services)

    assert len(results) == 2
    assert results[0]["exposure"] == "LOCAL"
    assert results[1]["exposure"] == "NETWORK"
