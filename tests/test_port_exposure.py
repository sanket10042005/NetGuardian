from security.port_exposure import (
    analyze_service,
    analyze_services
)


def test_ipv4_wildcard_service():
    service = {
        "protocol": "TCP",
        "address": "0.0.0.0",
        "port": 22
    }

    result = analyze_service(service)

    assert result["severity"] == "WARNING"
    assert result["exposure"] == "NETWORK"


def test_ipv6_wildcard_service():
    service = {
        "protocol": "TCP",
        "address": "::",
        "port": 443
    }

    result = analyze_service(service)

    assert result["severity"] == "WARNING"
    assert result["exposure"] == "NETWORK"


def test_ipv4_localhost_service():
    service = {
        "protocol": "TCP",
        "address": "127.0.0.1",
        "port": 631
    }

    result = analyze_service(service)

    assert result["severity"] == "INFO"
    assert result["exposure"] == "LOCAL"


def test_ipv6_localhost_service():
    service = {
        "protocol": "TCP",
        "address": "::1",
        "port": 631
    }

    result = analyze_service(service)

    assert result["severity"] == "INFO"
    assert result["exposure"] == "LOCAL"


def test_specific_interface_service():
    service = {
        "protocol": "TCP",
        "address": "192.168.1.83",
        "port": 8080
    }

    result = analyze_service(service)

    assert result["severity"] == "REVIEW"
    assert result["exposure"] == "SPECIFIC_INTERFACE"


def test_ipv6_zone_identifier():
    service = {
        "protocol": "TCP",
        "address": "fe80::1%wlp0s20f3",
        "port": 8080
    }

    result = analyze_service(service)

    assert result["severity"] == "REVIEW"
    assert result["exposure"] == "SPECIFIC_INTERFACE"


def test_bracketed_ipv6_address():
    service = {
        "protocol": "TCP",
        "address": "[::1]",
        "port": 631
    }

    result = analyze_service(service)

    assert result["severity"] == "INFO"
    assert result["exposure"] == "LOCAL"


def test_analyze_multiple_services():
    services = [
        {
            "protocol": "TCP",
            "address": "0.0.0.0",
            "port": 22
        },
        {
            "protocol": "TCP",
            "address": "127.0.0.1",
            "port": 631
        }
    ]

    findings = analyze_services(services)

    assert len(findings) == 2
    assert findings[0]["severity"] == "WARNING"
    assert findings[1]["severity"] == "INFO"
