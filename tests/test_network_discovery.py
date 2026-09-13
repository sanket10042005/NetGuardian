from discovery.network import discover_network_interfaces


def test_discover_network_interfaces_returns_list():
    interfaces = discover_network_interfaces()

    assert isinstance(interfaces, list)


def test_discovered_interfaces_have_required_fields():
    interfaces = discover_network_interfaces()

    for interface in interfaces:
        assert "name" in interface
        assert "is_up" in interface
        assert "ipv4_addresses" in interface
        assert "ipv6_addresses" in interface
        assert "mac_address" in interface
        assert "mtu" in interface


def test_discovered_interface_types_are_correct():
    interfaces = discover_network_interfaces()

    for interface in interfaces:
        assert isinstance(interface["name"], str)
        assert isinstance(interface["is_up"], bool)
        assert isinstance(interface["ipv4_addresses"], list)
        assert isinstance(interface["ipv6_addresses"], list)
        assert isinstance(interface["mtu"], int)


def test_ipv4_address_structure():
    interfaces = discover_network_interfaces()

    for interface in interfaces:
        for address in interface["ipv4_addresses"]:
            assert "address" in address
            assert "netmask" in address
            assert isinstance(address["address"], str)
            assert isinstance(address["netmask"], str)


def test_ipv6_address_structure():
    interfaces = discover_network_interfaces()

    for interface in interfaces:
        for address in interface["ipv6_addresses"]:
            assert "address" in address
            assert "netmask" in address
            assert isinstance(address["address"], str)
            assert isinstance(address["netmask"], str)
