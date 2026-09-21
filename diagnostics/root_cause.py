def analyze_root_cause(evidence):
    """
    Analyze collected network evidence and determine
    the most likely network condition.

    Expected evidence:
        interface_up
        gateway_detected
        gateway_reachable
        default_route_present
        internet_reachable

    Returns:
        A structured diagnostic result containing:
            status
            severity
            failure_domain
            finding
            recommendation
    """

    interface_up = evidence.get("interface_up")
    gateway_detected = evidence.get("gateway_detected")
    gateway_reachable = evidence.get("gateway_reachable")
    default_route_present = evidence.get(
        "default_route_present"
    )
    internet_reachable = evidence.get(
        "internet_reachable"
    )

    if interface_up is False:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "failure_domain": "INTERFACE",
            "finding": (
                "The network interface is down."
            ),
            "recommendation": (
                "Check the network interface state, "
                "physical or wireless connectivity, "
                "and interface configuration."
            )
        }

    if interface_up is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "failure_domain": "INTERFACE",
            "finding": (
                "Network interface state could not be determined."
            ),
            "recommendation": (
                "Inspect the available network interface "
                "information and verify the interface state."
            )
        }

    if gateway_detected is False:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "failure_domain": "GATEWAY",
            "finding": (
                "No default gateway was detected."
            ),
            "recommendation": (
                "Check the host network configuration "
                "and verify that a default gateway is assigned."
            )
        }

    if gateway_detected is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "failure_domain": "GATEWAY",
            "finding": (
                "Default gateway state could not be determined."
            ),
            "recommendation": (
                "Inspect the routing configuration and "
                "verify whether a default gateway is available."
            )
        }

    if default_route_present is False:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "failure_domain": "ROUTING",
            "finding": (
                "No default route was detected."
            ),
            "recommendation": (
                "Check the routing table and verify that "
                "a valid default route is configured."
            )
        }

    if default_route_present is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "failure_domain": "ROUTING",
            "finding": (
                "Default route state could not be determined."
            ),
            "recommendation": (
                "Inspect the routing table and verify "
                "the default route configuration."
            )
        }

    if gateway_reachable is False:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "failure_domain": "GATEWAY",
            "finding": (
                "The default gateway is unreachable."
            ),
            "recommendation": (
                "Check connectivity between the host and "
                "the default gateway, including local network "
                "configuration and link connectivity."
            )
        }

    if gateway_reachable is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "failure_domain": "GATEWAY",
            "finding": (
                "Gateway reachability could not be determined."
            ),
            "recommendation": (
                "Verify the gateway address and perform "
                "a connectivity test to the gateway."
            )
        }

    if internet_reachable is False:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "failure_domain": "UPSTREAM",
            "finding": (
                "The gateway is reachable, but external "
                "network connectivity is unavailable."
            ),
            "recommendation": (
                "Investigate upstream connectivity, "
                "WAN/ISP access, external routing, or "
                "network security controls."
            )
        }

    if internet_reachable is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "failure_domain": "UPSTREAM",
            "finding": (
                "External connectivity was not tested."
            ),
            "recommendation": (
                "Run an external connectivity test before "
                "determining the network's external health."
            )
        }

    return {
        "status": "HEALTHY",
        "severity": "INFO",
        "failure_domain": "NONE",
        "finding": (
            "The network interface, default route, "
            "gateway, and external connectivity are healthy."
        ),
        "recommendation": (
            "No action is required based on the "
            "current network evidence."
        )
    }
