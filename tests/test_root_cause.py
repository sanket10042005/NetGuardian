from diagnostics.root_cause import analyze_root_cause


def test_healthy_network():
    evidence = {
        "interface_up": True,
        "gateway_detected": True,
        "gateway_reachable": True,
        "default_route_present": True,
        "internet_reachable": True
    }

    result = analyze_root_cause(evidence)

    assert result["status"] == "HEALTHY"
    assert result["severity"] == "INFO"


def test_interface_down():
    evidence = {
        "interface_up": False,
        "gateway_detected": True,
        "gateway_reachable": True,
        "default_route_present": True,
        "internet_reachable": True
    }

    result = analyze_root_cause(evidence)

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "interface" in result["finding"].lower()


def test_no_gateway():
    evidence = {
        "interface_up": True,
        "gateway_detected": False,
        "gateway_reachable": False,
        "default_route_present": False,
        "internet_reachable": False
    }

    result = analyze_root_cause(evidence)

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "gateway" in result["finding"].lower()


def test_gateway_unreachable():
    evidence = {
        "interface_up": True,
        "gateway_detected": True,
        "gateway_reachable": False,
        "default_route_present": True,
        "internet_reachable": False
    }

    result = analyze_root_cause(evidence)

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "gateway" in result["finding"].lower()


def test_no_default_route():
    evidence = {
        "interface_up": True,
        "gateway_detected": True,
        "gateway_reachable": True,
        "default_route_present": False,
        "internet_reachable": False
    }

    result = analyze_root_cause(evidence)

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "route" in result["finding"].lower()


def test_internet_unreachable():
    evidence = {
        "interface_up": True,
        "gateway_detected": True,
        "gateway_reachable": True,
        "default_route_present": True,
        "internet_reachable": False
    }

    result = analyze_root_cause(evidence)

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "external" in result["finding"].lower()


def test_missing_external_test():
    evidence = {
        "interface_up": True,
        "gateway_detected": True,
        "gateway_reachable": True,
        "default_route_present": True,
        "internet_reachable": None
    }

    result = analyze_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["severity"] == "MEDIUM"


def test_upstream_recommendation():
    evidence = {
        "interface_up": True,
        "gateway_detected": True,
        "gateway_reachable": True,
        "default_route_present": True,
        "internet_reachable": False
    }

    result = analyze_root_cause(evidence)

    assert "recommendation" in result
    assert "upstream" in result["recommendation"].lower()


def test_healthy_recommendation():
    evidence = {
        "interface_up": True,
        "gateway_detected": True,
        "gateway_reachable": True,
        "default_route_present": True,
        "internet_reachable": True
    }

    result = analyze_root_cause(evidence)

    assert "recommendation" in result
    assert "no action" in result["recommendation"].lower()
