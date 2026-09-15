
from security.firewall_monitor import (
    command_exists,
    get_ufw_status,
    get_nftables_status,
    get_iptables_status,
    discover_firewalls
)


def test_command_exists_for_python():
    assert command_exists("python3") is True


def test_command_does_not_exist():
    assert command_exists("netguardian-command-that-does-not-exist") is False


def test_ufw_status_structure():
    result = get_ufw_status()

    assert "available" in result
    assert "status" in result

    assert isinstance(result["available"], bool)
    assert isinstance(result["status"], str)


def test_nftables_status_structure():
    result = get_nftables_status()

    assert "available" in result
    assert "status" in result

    assert isinstance(result["available"], bool)
    assert isinstance(result["status"], str)


def test_iptables_status_structure():
    result = get_iptables_status()

    assert "available" in result
    assert "status" in result

    assert isinstance(result["available"], bool)
    assert isinstance(result["status"], str)


def test_firewall_discovery_structure():
    result = discover_firewalls()

    assert "ufw" in result
    assert "nftables" in result
    assert "iptables" in result


def test_firewall_discovery_contains_status():
    result = discover_firewalls()

    for firewall in result.values():
        assert "available" in firewall
        assert "status" in firewall
