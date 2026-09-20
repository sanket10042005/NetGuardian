from diagnostics.network_evidence import collect_network_evidence


def test_network_evidence_structure():
    result = collect_network_evidence()

    assert "interface_up" in result
    assert "gateway_detected" in result
    assert "gateway_reachable" in result
    assert "default_route_present" in result
    assert "internet_reachable" in result

    assert "gateway" in result
    assert "gateway_packet_loss" in result
    assert "gateway_latency" in result

    assert "default_route" in result

    assert "network_target" in result
    assert "internet_packet_loss" in result
    assert "internet_latency" in result


def test_network_evidence_without_external_target():
    result = collect_network_evidence()

    assert result["network_target"] is None
    assert result["internet_reachable"] is None
    assert result["internet_packet_loss"] is None
    assert result["internet_latency"] is None


def test_network_evidence_boolean_values():
    result = collect_network_evidence()

    assert result["interface_up"] in (
        True,
        False,
        None
    )

    assert result["gateway_detected"] in (
        True,
        False
    )

    assert result["gateway_reachable"] in (
        True,
        False
    )

    assert result["default_route_present"] in (
        True,
        False
    )


def test_network_evidence_with_external_target():
    result = collect_network_evidence("1.1.1.1")

    assert result["network_target"] == "1.1.1.1"

    assert result["internet_reachable"] in (
        True,
        False
    )

    if result["internet_reachable"]:
        assert result["internet_packet_loss"] is not None
        assert result["internet_latency"] is not None
