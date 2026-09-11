from port_monitor import check_port


def test_open_port():
    result = check_port("127.0.0.1", 22)

    assert result["host"] == "127.0.0.1"
    assert result["port"] == 22
    assert result["open"] is True


def test_closed_port():
    result = check_port("127.0.0.1", 9999)

    assert result["host"] == "127.0.0.1"
    assert result["port"] == 9999
    assert result["open"] is False
