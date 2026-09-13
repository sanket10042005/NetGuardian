from port_monitor import check_port, get_socket_family


def test_get_socket_family_ipv4():
    family = get_socket_family("127.0.0.1")

    assert family != 0


def test_get_socket_family_ipv6():
    family = get_socket_family("::1")

    assert family != 0


def test_get_socket_family_invalid():
    family = get_socket_family("invalid-host")

    assert family == 0


def test_open_port():
    result = check_port("127.0.0.1", 22)

    assert result["host"] == "127.0.0.1"
    assert result["port"] == 22
    assert result["open"] is True


def test_ipv6_port():
    result = check_port("::1", 631)

    assert result["host"] == "::1"
    assert result["port"] == 631
    assert result["open"] is True


def test_closed_port():
    result = check_port("127.0.0.1", 9999)

    assert result["host"] == "127.0.0.1"
    assert result["port"] == 9999
    assert result["open"] is False


def test_invalid_host():
    result = check_port("invalid-host", 22)

    assert result["host"] == "invalid-host"
    assert result["port"] == 22
    assert result["open"] is False
