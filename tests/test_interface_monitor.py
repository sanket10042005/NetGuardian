from interface_monitor import get_network_interfaces


def test_network_interfaces():
    interfaces = get_network_interfaces()

    assert isinstance(interfaces, list)
    assert len(interfaces) > 0

    for interface in interfaces:
        assert "name" in interface
        assert "is_up" in interface
        assert "ip_address" in interface
        assert "netmask" in interface
        assert "mac_address" in interface
        assert "mtu" in interface


def test_loopback_interface():
    interfaces = get_network_interfaces()

    loopback = None

    for interface in interfaces:
        if interface["name"] == "lo":
            loopback = interface
            break

    assert loopback is not None
    assert loopback["is_up"] is True
    assert loopback["ip_address"] == "127.0.0.1"
