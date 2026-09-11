from network_monitor import parse_packet_loss, parse_average_latency


def test_parse_packet_loss():
    output = "4 packets transmitted, 4 received, 0% packet loss, time 3004ms"

    result = parse_packet_loss(output)

    assert result == 0.0


def test_parse_average_latency():
    output = "rtt min/avg/max/mdev = 5.540/5.762/5.999/0.170 ms"

    result = parse_average_latency(output)

    assert result == 5.762
