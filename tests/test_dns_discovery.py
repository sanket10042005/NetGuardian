from discovery.dns import discover_dns_servers


def test_discover_dns_servers_returns_list():
    dns_servers = discover_dns_servers()

    assert isinstance(dns_servers, list)


def test_discovered_dns_servers_are_strings():
    dns_servers = discover_dns_servers()

    for server in dns_servers:
        assert isinstance(server, str)


def test_discovered_dns_servers_are_not_empty():
    dns_servers = discover_dns_servers()

    for server in dns_servers:
        assert server.strip() != ""


def test_discovered_dns_servers_are_unique():
    dns_servers = discover_dns_servers()

    assert len(dns_servers) == len(set(dns_servers))
