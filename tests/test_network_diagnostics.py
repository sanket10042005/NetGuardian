from diagnostics.network_diagnostics import (
    diagnose_gateway,
    diagnose_gateway_with_route,
    diagnose_default_route,
    diagnose_network,
    diagnose_internet_reachability,
    diagnose_full_network
)


# ============================================================
# Gateway Diagnosis Tests
# ============================================================

def test_gateway_healthy():
    result = diagnose_gateway(
        "192.168.1.1",
        True,
        True
    )

    assert result["status"] == "HEALTHY"
    assert result["severity"] == "INFO"


def test_gateway_unreachable():
    result = diagnose_gateway(
        "192.168.1.1",
        False,
        True
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "gateway is unreachable" in result["finding"]


def test_gateway_not_detected():
    result = diagnose_gateway(
        None,
        False,
        True
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "No default gateway" in result["finding"]


def test_interface_down():
    result = diagnose_gateway(
        "192.168.1.1",
        False,
        False
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "network interface is down" in result["finding"]


# ============================================================
# Gateway + Route Diagnosis Tests
# ============================================================

def test_gateway_route_healthy():
    result = diagnose_gateway_with_route(
        "192.168.1.1",
        True,
        True,
        True
    )

    assert result["status"] == "HEALTHY"
    assert result["severity"] == "INFO"


def test_gateway_route_missing():
    result = diagnose_gateway_with_route(
        "192.168.1.1",
        False,
        True,
        False
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "No route to the gateway" in result["finding"]


def test_gateway_unreachable_with_route():
    result = diagnose_gateway_with_route(
        "192.168.1.1",
        False,
        True,
        True
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "gateway is unreachable" in result["finding"]


def test_gateway_reachable_without_route():
    result = diagnose_gateway_with_route(
        "192.168.1.1",
        True,
        True,
        False
    )

    assert result["status"] == "REVIEW"
    assert result["severity"] == "MEDIUM"
    assert "no route" in result["finding"]


def test_gateway_route_with_interface_down():
    result = diagnose_gateway_with_route(
        "192.168.1.1",
        False,
        False,
        True
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "network interface is down" in result["finding"]


# ============================================================
# Default Route Diagnosis Tests
# ============================================================

def test_default_route_healthy():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_default_route(
        "192.168.1.1",
        route,
        True
    )

    assert result["status"] == "HEALTHY"
    assert result["severity"] == "INFO"


def test_default_route_missing():
    result = diagnose_default_route(
        "192.168.1.1",
        None,
        True
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "No default route" in result["finding"]


def test_default_route_wrong_gateway():
    route = {
        "destination": "default",
        "gateway": "192.168.1.50",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_default_route(
        "192.168.1.200",
        route,
        True
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "different gateway" in result["finding"]


def test_default_route_interface_down():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_default_route(
        "192.168.1.1",
        route,
        False
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "interface is down" in result["finding"]


def test_default_route_missing_interface():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": None,
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_default_route(
        "192.168.1.1",
        route,
        True
    )

    assert result["status"] == "REVIEW"
    assert result["severity"] == "MEDIUM"
    assert "no interface" in result["finding"]


def test_default_route_missing_source_ip():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": None,
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_default_route(
        "192.168.1.1",
        route,
        True
    )

    assert result["status"] == "REVIEW"
    assert result["severity"] == "MEDIUM"
    assert "no source IP" in result["finding"]


def test_wrong_route_type():
    route = {
        "destination": "192.168.1.0/24",
        "gateway": None,
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "kernel",
        "metric": 600
    }

    result = diagnose_default_route(
        "192.168.1.1",
        route,
        True
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "not a default route" in result["finding"]


# ============================================================
# Combined Network Diagnosis Tests
# ============================================================

def test_combined_network_healthy():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_network(
        "192.168.1.1",
        True,
        True,
        route
    )

    assert result["status"] == "HEALTHY"
    assert result["severity"] == "INFO"


def test_combined_network_interface_down():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_network(
        "192.168.1.1",
        True,
        False,
        route
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "interface is down" in result["finding"]


def test_combined_network_no_gateway():
    result = diagnose_network(
        None,
        False,
        True,
        None
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "No default gateway" in result["finding"]


def test_combined_network_no_route():
    result = diagnose_network(
        "192.168.1.1",
        False,
        True,
        None
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "No default route" in result["finding"]


def test_combined_network_wrong_gateway():
    route = {
        "destination": "default",
        "gateway": "192.168.1.50",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_network(
        "192.168.1.200",
        True,
        True,
        route
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "different" in result["finding"]


def test_combined_network_missing_interface():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": None,
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_network(
        "192.168.1.1",
        True,
        True,
        route
    )

    assert result["status"] == "REVIEW"
    assert result["severity"] == "MEDIUM"
    assert "no interface" in result["finding"]


def test_combined_network_missing_source_ip():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": None,
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_network(
        "192.168.1.1",
        True,
        True,
        route
    )

    assert result["status"] == "REVIEW"
    assert result["severity"] == "MEDIUM"
    assert "no source IP" in result["finding"]


def test_combined_network_gateway_unreachable():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_network(
        "192.168.1.1",
        False,
        True,
        route
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "gateway is unreachable" in result["finding"]


# ============================================================
# Internet Reachability Diagnosis Tests
# ============================================================

def test_internet_reachability_healthy():
    result = diagnose_internet_reachability(
        "external-target",
        True,
        0.0,
        7.5
    )

    assert result["status"] == "HEALTHY"
    assert result["severity"] == "INFO"
    assert result["target"] == "external-target"
    assert result["packet_loss"] == 0.0
    assert result["latency"] == 7.5
    assert "reachable" in result["finding"]


def test_internet_reachability_unreachable():
    result = diagnose_internet_reachability(
        "external-target",
        False,
        100.0,
        None
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert result["target"] == "external-target"
    assert result["packet_loss"] == 100.0
    assert result["latency"] is None
    assert "unreachable" in result["finding"]


def test_internet_reachability_no_target():
    result = diagnose_internet_reachability(
        None,
        False,
        None,
        None
    )

    assert result["status"] == "REVIEW"
    assert result["severity"] == "MEDIUM"
    assert result["target"] is None
    assert "No external connectivity test target" in result["finding"]


# ============================================================
# Full Network Diagnosis Tests
# ============================================================

def test_full_network_healthy():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_full_network(
        "192.168.1.1",
        True,
        True,
        route,
        True
    )

    assert result["status"] == "HEALTHY"
    assert result["severity"] == "INFO"
    assert "all healthy" in result["finding"]


def test_full_network_interface_down():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_full_network(
        "192.168.1.1",
        False,
        False,
        route,
        False
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "interface is down" in result["finding"]


def test_full_network_no_gateway():
    result = diagnose_full_network(
        None,
        False,
        True,
        None,
        False
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "No default gateway" in result["finding"]


def test_full_network_no_route():
    result = diagnose_full_network(
        "192.168.1.1",
        False,
        True,
        None,
        False
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "No default route" in result["finding"]


def test_full_network_wrong_gateway():
    route = {
        "destination": "default",
        "gateway": "192.168.1.50",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_full_network(
        "192.168.1.200",
        True,
        True,
        route,
        True
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "different gateway" in result["finding"]


def test_full_network_missing_interface():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": None,
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_full_network(
        "192.168.1.1",
        True,
        True,
        route,
        True
    )

    assert result["status"] == "REVIEW"
    assert result["severity"] == "MEDIUM"
    assert "no interface" in result["finding"]


def test_full_network_missing_source_ip():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": None,
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_full_network(
        "192.168.1.1",
        True,
        True,
        route,
        True
    )

    assert result["status"] == "REVIEW"
    assert result["severity"] == "MEDIUM"
    assert "no source IP" in result["finding"]


def test_full_network_gateway_unreachable():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_full_network(
        "192.168.1.1",
        False,
        True,
        route,
        False
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "gateway is unreachable" in result["finding"]


def test_full_network_internet_unreachable():
    route = {
        "destination": "default",
        "gateway": "192.168.1.1",
        "interface": "wlp0s20f3",
        "source_ip": "192.168.1.83",
        "protocol": "dhcp",
        "metric": 600
    }

    result = diagnose_full_network(
        "192.168.1.1",
        True,
        True,
        route,
        False
    )

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert "external network connectivity" in result["finding"]
