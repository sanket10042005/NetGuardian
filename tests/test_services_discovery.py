from unittest.mock import Mock, patch

from discovery.services import (
    discover_tcp_services,
    normalize_address,
    parse_process_owners,
    parse_tcp_services
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


def test_parse_process_owners_extracts_name_and_pid():
    line = (
        'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    assert parse_process_owners(line) == [
        {
            "process_name": "sample-service",
            "pid": 4321
        }
    ]


def test_parse_process_owners_supports_multiple_owners():
    line = (
        'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
        'users:(("service-one",pid=123,fd=5),'
        '("service-two",pid=456,fd=6))'
    )

    assert parse_process_owners(line) == [
        {
            "process_name": "service-one",
            "pid": 123
        },
        {
            "process_name": "service-two",
            "pid": 456
        }
    ]


def test_parse_process_owners_returns_empty_list_when_unavailable():
    line = (
        "LISTEN 0 128 127.0.0.1:45678 "
        "0.0.0.0:*"
    )

    assert parse_process_owners(line) == []


def test_parse_tcp_services_preserves_original_fields():
    output = (
        'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    services = parse_tcp_services(output)

    assert len(services) == 1
    assert services[0]["protocol"] == "TCP"
    assert services[0]["address"] == "127.0.0.1"
    assert services[0]["port"] == 45678


def test_parse_tcp_services_includes_process_ownership():
    output = (
        'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    service = parse_tcp_services(output)[0]

    assert service["process_name"] == "sample-service"
    assert service["pid"] == 4321
    assert service["ownership_status"] == "AVAILABLE"
    assert service["process_owners"] == [
        {
            "process_name": "sample-service",
            "pid": 4321
        }
    ]


def test_parse_tcp_services_handles_missing_ownership():
    output = (
        "LISTEN 0 128 127.0.0.1:45678 "
        "0.0.0.0:*"
    )

    service = parse_tcp_services(output)[0]

    assert service["process_name"] is None
    assert service["pid"] is None
    assert service["process_owners"] == []
    assert service["ownership_status"] == "UNAVAILABLE"


def test_parse_tcp_services_supports_ipv6():
    output = (
        'LISTEN 0 128 [::1]:45678 [::]:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    service = parse_tcp_services(output)[0]

    assert service["address"] == "[::1]"
    assert service["port"] == 45678


def test_parse_tcp_services_normalizes_wildcard():
    output = (
        'LISTEN 0 128 *:45678 *:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    service = parse_tcp_services(output)[0]

    assert service["address"] == "0.0.0.0"


def test_parse_tcp_services_ignores_malformed_lines():
    output = "\n".join(
        [
            "not valid output",
            "LISTEN incomplete",
            (
                "LISTEN 0 128 127.0.0.1:not-a-port "
                "0.0.0.0:*"
            ),
            (
                "LISTEN 0 128 127.0.0.1:70000 "
                "0.0.0.0:*"
            )
        ]
    )

    assert parse_tcp_services(output) == []


@patch("discovery.services.subprocess.run")
def test_discovery_uses_ss_without_automatic_sudo(mock_run):
    mock_run.return_value = Mock(
        stdout=(
            'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
            'users:(("sample-service",pid=4321,fd=5))'
        )
    )

    services = discover_tcp_services()

    assert len(services) == 1
    assert services[0]["process_name"] == "sample-service"

    command = mock_run.call_args.args[0]

    assert command == ["ss", "-ltnpH"]
    assert "sudo" not in command


@patch("discovery.services.subprocess.run")
def test_discovery_handles_command_failure(mock_run):
    import subprocess

    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=1,
        cmd=["ss", "-ltnpH"]
    )

    assert discover_tcp_services() == []
