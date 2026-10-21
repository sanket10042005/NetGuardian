from unittest.mock import Mock, patch

from discovery.services import (
    discover_tcp_services,
    discover_udp_sockets,
    normalize_address,
    parse_process_owners,
    parse_tcp_services,
    parse_udp_sockets,
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


def test_discovered_services_have_valid_ports():
    services = discover_tcp_services()

    for service in services:
        assert 1 <= service["port"] <= 65535


def test_discovered_services_are_unique():
    services = discover_tcp_services()

    assert len(services) == len(
        [
            str(service)
            for service in services
        ]
    )


def test_parse_process_owners():
    line = (
        'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    owners = parse_process_owners(line)

    assert owners == [
        {
            "process_name": "sample-service",
            "pid": 4321,
        }
    ]


def test_parse_process_owners_multiple_processes():
    line = (
        'users:(("service-one",pid=1234,fd=5),'
        '("service-two",pid=5678,fd=6))'
    )

    owners = parse_process_owners(line)

    assert owners == [
        {
            "process_name": "service-one",
            "pid": 1234,
        },
        {
            "process_name": "service-two",
            "pid": 5678,
        },
    ]


def test_parse_process_owners_without_process_information():
    line = "LISTEN 0 128 127.0.0.1:45678 0.0.0.0:*"

    assert parse_process_owners(line) == []


def test_parse_tcp_services_preserves_original_fields():
    output = (
        'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    service = parse_tcp_services(output)[0]

    assert service["protocol"] == "TCP"
    assert service["address"] == "127.0.0.1"
    assert service["port"] == 45678
    assert service["process_name"] == "sample-service"
    assert service["pid"] == 4321


def test_parse_tcp_services_includes_process_ownership():
    output = (
        'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    service = parse_tcp_services(output)[0]

    assert service["process_owners"] == [
        {
            "process_name": "sample-service",
            "pid": 4321,
        }
    ]


def test_parse_tcp_services_handles_missing_ownership():
    output = (
        "LISTEN 0 128 127.0.0.1:45678 "
        "0.0.0.0:*"
    )

    service = parse_tcp_services(output)[0]

    assert service["process_owners"] == []
    assert service["process_name"] is None
    assert service["pid"] is None
    assert service["ownership_status"] == "UNAVAILABLE"


def test_parse_tcp_services_supports_ipv6():
    output = (
        "LISTEN 0 128 [::1]:45678 [::]:*"
    )

    services = parse_tcp_services(output)

    assert len(services) == 1
    assert services[0]["address"] == "[::1]"
    assert services[0]["port"] == 45678


def test_parse_tcp_services_normalizes_wildcard():
    output = (
        "LISTEN 0 128 *:45678 *:*"
    )

    services = parse_tcp_services(output)

    assert len(services) == 1
    assert services[0]["address"] == "0.0.0.0"


def test_parse_tcp_services_ignores_malformed_lines():
    output = """
    malformed input
    LISTEN 0 128 invalid-address 0.0.0.0:*
    LISTEN 0 128 127.0.0.1:invalid 0.0.0.0:*
    """

    assert parse_tcp_services(output) == []


def test_parse_tcp_services_reports_ownership_source():
    output = (
        'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    service = parse_tcp_services(output)[0]

    assert service["ownership_source"] == "ss"


def test_parse_tcp_services_reports_available_ownership_note():
    output = (
        'LISTEN 0 128 127.0.0.1:45678 0.0.0.0:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    service = parse_tcp_services(output)[0]

    assert service["ownership_status"] == "AVAILABLE"
    assert service["ownership_note"] == (
        "Process ownership was discovered."
    )


def test_parse_tcp_services_reports_unavailable_ownership_note():
    output = (
        "LISTEN 0 128 127.0.0.1:45678 "
        "0.0.0.0:*"
    )

    service = parse_tcp_services(output)[0]

    assert service["ownership_status"] == "UNAVAILABLE"
    assert service["ownership_note"] == (
        "Process ownership could not be verified "
        "with the current visibility."
    )


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
        cmd=["ss", "-ltnpH"],
    )

    assert discover_tcp_services() == []


# =========================================================
# UDP DISCOVERY TESTS
# =========================================================


def test_parse_udp_sockets_ipv4():
    output = (
        "UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*"
    )

    services = parse_udp_sockets(output)

    assert len(services) == 1
    assert services[0]["protocol"] == "UDP"
    assert services[0]["address"] == "127.0.0.1"
    assert services[0]["port"] == 5353


def test_parse_udp_sockets_ipv6():
    output = (
        "UNCONN 0 0 [::1]:5353 [::]:*"
    )

    services = parse_udp_sockets(output)

    assert len(services) == 1
    assert services[0]["protocol"] == "UDP"
    assert services[0]["address"] == "[::1]"
    assert services[0]["port"] == 5353


def test_parse_udp_sockets_with_process_owner():
    output = (
        'UNCONN 0 0 127.0.0.1:5353 0.0.0.0:* '
        'users:(("sample-service",pid=4321,fd=5))'
    )

    service = parse_udp_sockets(output)[0]

    assert service["process_name"] == "sample-service"
    assert service["pid"] == 4321
    assert service["ownership_status"] == "AVAILABLE"


def test_parse_udp_sockets_without_process_owner():
    output = (
        "UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*"
    )

    service = parse_udp_sockets(output)[0]

    assert service["process_owners"] == []
    assert service["process_name"] is None
    assert service["pid"] is None
    assert service["ownership_status"] == "UNAVAILABLE"


def test_parse_udp_sockets_ignores_malformed_lines():
    output = """
    malformed input
    UNCONN 0 0 invalid-address 0.0.0.0:*
    UNCONN 0 0 127.0.0.1:invalid 0.0.0.0:*
    """

    assert parse_udp_sockets(output) == []


@patch("discovery.services.subprocess.run")
def test_discover_udp_sockets_uses_ss_without_sudo(mock_run):
    mock_run.return_value = Mock(
        stdout="UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*"
    )

    services = discover_udp_sockets()

    assert len(services) == 1
    assert services[0]["protocol"] == "UDP"

    command = mock_run.call_args.args[0]

    assert command == ["ss", "-lunpH"]
    assert "sudo" not in command


@patch("discovery.services.subprocess.run")
def test_discover_udp_sockets_handles_command_failure(mock_run):
    import subprocess

    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=1,
        cmd=["ss", "-lunpH"],
    )

    assert discover_udp_sockets() == []
