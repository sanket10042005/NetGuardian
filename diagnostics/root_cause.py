
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
            "finding": (
                "The network interface is down."
            )
        }

    if interface_up is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "Network interface state could not be determined."
            )
        }

    if gateway_detected is False:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "No default gateway was detected."
            )
        }

    if gateway_detected is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "Default gateway state could not be determined."
            )
        }

    if default_route_present is False:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "No default route was detected."
            )
        }

    if default_route_present is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "Default route state could not be determined."
            )
        }

    if gateway_reachable is False:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The default gateway is unreachable."
            )
        }

    if gateway_reachable is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "Gateway reachability could not be determined."
            )
        }

    if internet_reachable is False:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The gateway is reachable, but external "
                "network connectivity is unavailable."
            )
        }

    if internet_reachable is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "External connectivity was not tested."
            )
        }

    return {
        "status": "HEALTHY",
        "severity": "INFO",
        "finding": (
            "The network interface, default route, "
            "gateway, and external connectivity are healthy."
        )
    }
