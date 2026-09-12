
from route_monitor import parse_routing_table


def test_parse_default_route():
    output = (
        "default via 192.168.1.200 dev wlp0s20f3 "
        "proto dhcp src 192.168.1.83 metric 600"
    )

    routes = parse_routing_table(output)

    assert len(routes) == 1

    route = routes[0]

    assert route["destination"] == "default"
    assert route["gateway"] == "192.168.1.200"
    assert route["interface"] == "wlp0s20f3"
    assert route["source_ip"] == "192.168.1.83"
    assert route["protocol"] == "dhcp"
    assert route["metric"] == 600


def test_parse_connected_route():
    output = (
        "192.168.1.0/24 dev wlp0s20f3 "
        "proto kernel scope link src 192.168.1.83 metric 600"
    )

    routes = parse_routing_table(output)

    assert len(routes) == 1

    route = routes[0]

    assert route["destination"] == "192.168.1.0/24"
    assert route["gateway"] is None
    assert route["interface"] == "wlp0s20f3"
    assert route["source_ip"] == "192.168.1.83"
    assert route["protocol"] == "kernel"
    assert route["metric"] == 600


def test_parse_multiple_routes():
    output = (
        "default via 192.168.1.200 dev wlp0s20f3 "
        "proto dhcp src 192.168.1.83 metric 600\n"
        "192.168.1.0/24 dev wlp0s20f3 "
        "proto kernel scope link src 192.168.1.83 metric 600"
    )

    routes = parse_routing_table(output)

    assert len(routes) == 2
    assert routes[0]["destination"] == "default"
    assert routes[1]["destination"] == "192.168.1.0/24"
