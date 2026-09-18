from security.security_assessment import assess_service_security


def test_network_service_with_inactive_firewall():
    service_finding = {
        "protocol": "TCP",
        "address": "0.0.0.0",
        "port": 22,
        "exposure": "NETWORK"
    }

    result = assess_service_security(
        service_finding,
        "INACTIVE"
    )

    assert result["severity"] == "HIGH"
    assert result["firewall_status"] == "INACTIVE"


def test_network_service_with_no_firewall_rules():
    service_finding = {
        "protocol": "TCP",
        "address": "::",
        "port": 443,
        "exposure": "NETWORK"
    }

    result = assess_service_security(
        service_finding,
        "NO_RULES"
    )

    assert result["severity"] == "HIGH"


def test_network_service_with_access_denied():
    service_finding = {
        "protocol": "TCP",
        "address": "0.0.0.0",
        "port": 22,
        "exposure": "NETWORK"
    }

    result = assess_service_security(
        service_finding,
        "ACCESS_DENIED"
    )

    assert result["severity"] == "REVIEW"
    assert "elevated privileges" in result["message"]


def test_network_service_with_error():
    service_finding = {
        "protocol": "TCP",
        "address": "0.0.0.0",
        "port": 22,
        "exposure": "NETWORK"
    }

    result = assess_service_security(
        service_finding,
        "ERROR"
    )

    assert result["severity"] == "REVIEW"
    assert "inspection failed" in result["message"]


def test_network_service_with_unknown_firewall():
    service_finding = {
        "protocol": "TCP",
        "address": "0.0.0.0",
        "port": 22,
        "exposure": "NETWORK"
    }

    result = assess_service_security(
        service_finding,
        "UNKNOWN"
    )

    assert result["severity"] == "REVIEW"
    assert "firewall state is unknown" in result["message"]


def test_local_service():
    service_finding = {
        "protocol": "TCP",
        "address": "127.0.0.1",
        "port": 631,
        "exposure": "LOCAL"
    }

    result = assess_service_security(
        service_finding,
        "INACTIVE"
    )

    assert result["severity"] == "INFO"


def test_specific_interface_service():
    service_finding = {
        "protocol": "TCP",
        "address": "192.168.1.83",
        "port": 8080,
        "exposure": "SPECIFIC_INTERFACE"
    }

    result = assess_service_security(
        service_finding,
        "INACTIVE"
    )

    assert result["severity"] == "REVIEW"


def test_unknown_exposure():
    service_finding = {
        "protocol": "TCP",
        "address": "unknown",
        "port": 8080,
        "exposure": "UNKNOWN"
    }

    result = assess_service_security(
        service_finding,
        "ACCESS_DENIED"
    )

    assert result["severity"] == "REVIEW"
    assert "could not be fully classified" in result["message"]


def test_assessment_contains_required_information():
    service_finding = {
        "protocol": "TCP",
        "address": "0.0.0.0",
        "port": 22,
        "exposure": "NETWORK"
    }

    result = assess_service_security(
        service_finding,
        "INACTIVE"
    )

    assert result["protocol"] == "TCP"
    assert result["address"] == "0.0.0.0"
    assert result["port"] == 22
    assert result["exposure"] == "NETWORK"
    assert result["firewall_status"] == "INACTIVE"
    assert "severity" in result
    assert "message" in result
