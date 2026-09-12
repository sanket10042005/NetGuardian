from gateway_monitor import (
    get_default_gateway,
    check_gateway
)


def test_default_gateway():
    gateway = get_default_gateway()

    assert gateway is None or isinstance(gateway, str)

    if gateway is not None:
        parts = gateway.split(".")

        assert len(parts) == 4
        assert all(part.isdigit() for part in parts)
        assert all(0 <= int(part) <= 255 for part in parts)


def test_check_gateway():
    result = check_gateway()

    assert "gateway" in result
    assert "reachable" in result
    assert "packet_loss" in result
    assert "latency" in result

    if result["gateway"] is not None:
        assert isinstance(result["reachable"], bool)
