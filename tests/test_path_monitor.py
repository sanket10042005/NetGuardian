from path_monitor import get_route_to_host, parse_route


def test_parse_route_with_gateway():
    output = (
        "8.8.8.8 via 192.168.1.200 "
        "dev wlp0s20f3 src 192.168.1.83 uid 1000"
    )

    route = parse_route(output)

    assert route["destination"] == "8.8.8.8"
    assert route["gateway"] == "192.168.1.200"
    assert route["interface"] == "wlp0s20f3"
    assert route["source_ip"] == "192.168.1.83"


def test_parse_direct_route():
    output = (
        "192.168.1.200 dev wlp0s20f3 "
        "src 192.168.1.83 uid 1000"
    )

    route = parse_route(output)

    assert route["destination"] == "192.168.1.200"
    assert route["gateway"] is None
    assert route["interface"] == "wlp0s20f3"
    assert route["source_ip"] == "192.168.1.83"


def test_parse_route_with_additional_fields():
    output = (
        "1.1.1.1 via 192.168.1.200 "
        "dev wlp0s20f3 src 192.168.1.89 "
        "uid 1000 cache"
    )

    route = parse_route(output)

    assert route["destination"] == "1.1.1.1"
    assert route["gateway"] == "192.168.1.200"
    assert route["interface"] == "wlp0s20f3"
    assert route["source_ip"] == "192.168.1.89"


def test_parse_empty_output():
    route = parse_route(None)

    assert route is None


def test_parse_empty_string():
    route = parse_route("")

    assert route is None
