
from discovery.services import (
    discover_tcp_services,
    normalize_address
)
def test_normalize_wildcard_address():
    assert normalize_address("*") == "0.0.0.0"

def test_discover_tcp_services_returns_list():
    services = discover_tcp_services()

    assert isinstance(services, list)


def test_discovered_services_have_required_fields():
    services = discover_tcp_services()

    for service in services:
        assert "protocol" in service
        assert "address" in service
        assert "port" in service


def test_discovered_services_have_correct_types():
    services = discover_tcp_services()

    for service in services:
        assert service["protocol"] == "TCP"
        assert isinstance(service["address"], str)
        assert isinstance(service["port"], int)


def test_discovered_ports_are_valid():
    services = discover_tcp_services()

    for service in services:
        assert 1 <= service["port"] <= 65535


def test_discovered_services_are_unique():
    services = discover_tcp_services()

    assert len(services) == len(
        {
            (
                service["protocol"],
                service["address"],
                service["port"]
            )
            for service in services
        }
    )
