def diagnose_gateway(
    gateway,
    gateway_reachable,
    interface_up
):
    """
    Analyze gateway connectivity using collected network evidence.
    """

    if gateway is None:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "No default gateway was detected."
        }

    if not interface_up:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "The network interface is down."
        }

    if not gateway_reachable:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "The default gateway is unreachable."
        }

    return {
        "status": "HEALTHY",
        "severity": "INFO",
        "finding": "The default gateway is reachable."
    }


def diagnose_gateway_with_route(
    gateway,
    gateway_reachable,
    interface_up,
    route_exists
):
    """
    Analyze gateway connectivity together with route evidence.
    """

    if gateway is None:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "No default gateway was detected."
        }

    if not interface_up:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "The network interface is down."
        }

    if not route_exists:
        if gateway_reachable:
            return {
                "status": "REVIEW",
                "severity": "MEDIUM",
                "finding": (
                    "The gateway is reachable, but no route "
                    "to the gateway was detected."
                )
            }

        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "No route to the gateway was detected."
        }

    if not gateway_reachable:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "A route to the gateway exists, "
                "but the gateway is unreachable."
            )
        }

    return {
        "status": "HEALTHY",
        "severity": "INFO",
        "finding": (
            "The interface is up, a route exists, "
            "and the gateway is reachable."
        )
    }


def diagnose_default_route(
    gateway,
    route,
    interface_up
):
    """
    Analyze the discovered default route.

    The route is expected to contain:
        destination
        gateway
        interface
        source_ip
        protocol
        metric
    """

    if route is None:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "No default route was detected."
        }

    if route.get("destination") != "default":
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "The discovered route is not a default route."
        }

    if gateway is None:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "A default route exists, but no default gateway "
                "was detected."
            )
        }

    if route.get("gateway") != gateway:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The default route points to a different gateway "
                "than the discovered gateway."
            )
        }

    if not interface_up:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The default route exists, but its network "
                "interface is down."
            )
        }

    if not route.get("interface"):
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "The default route exists, but no interface "
                "was identified."
            )
        }

    if not route.get("source_ip"):
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "The default route exists, but no source IP "
                "was identified."
            )
        }

    return {
        "status": "HEALTHY",
        "severity": "INFO",
        "finding": (
            "The default route points to the discovered gateway "
            "through an active interface with a source IP."
        )
    }


def diagnose_network(
    gateway,
    gateway_reachable,
    interface_up,
    default_route
):
    """
    Combine gateway, interface, and default-route evidence
    into one network diagnosis.
    """

    if not interface_up:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "The network interface is down."
        }

    if gateway is None:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "No default gateway was detected."
        }

    if default_route is None:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": "No default route was detected."
        }

    if default_route.get("gateway") != gateway:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The default route points to a different "
                "gateway than the discovered gateway."
            )
        }

    if not default_route.get("interface"):
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "The default route exists, but no interface "
                "was identified."
            )
        }

    if not default_route.get("source_ip"):
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "The default route exists, but no source IP "
                "was identified."
            )
        }

    if not gateway_reachable:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The network interface and default route are "
                "present, but the gateway is unreachable."
            )
        }

    return {
        "status": "HEALTHY",
        "severity": "INFO",
        "finding": (
            "The network interface is up, the default route "
            "matches the gateway, and the gateway is reachable."
        )
    }


def diagnose_internet_reachability(
    target,
    reachable,
    packet_loss,
    latency
):
    """
    Analyze external network reachability using collected evidence.
    """

    if not target:
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "No external connectivity test target "
                "was provided."
            ),
            "target": target,
            "packet_loss": packet_loss,
            "latency": latency
        }

    if not reachable:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The external connectivity target is unreachable."
            ),
            "target": target,
            "packet_loss": packet_loss,
            "latency": latency
        }

    return {
        "status": "HEALTHY",
        "severity": "INFO",
        "finding": (
            "The external connectivity target is reachable."
        ),
        "target": target,
        "packet_loss": packet_loss,
        "latency": latency
    }


def diagnose_full_network(
    gateway,
    gateway_reachable,
    interface_up,
    default_route,
    internet_reachable
):
    """
    Combine local interface, gateway, route, and external
    connectivity evidence into one network diagnosis.
    """

    if not interface_up:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The active network interface is down."
            )
        }

    if gateway is None:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "No default gateway was detected."
            )
        }

    if default_route is None:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "No default route was detected."
            )
        }

    if default_route.get("gateway") != gateway:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The default route points to a different "
                "gateway than the discovered gateway."
            )
        }

    if not default_route.get("interface"):
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "The default route exists, but no interface "
                "was identified."
            )
        }

    if not default_route.get("source_ip"):
        return {
            "status": "REVIEW",
            "severity": "MEDIUM",
            "finding": (
                "The default route exists, but no source IP "
                "was identified."
            )
        }

    if not gateway_reachable:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The local interface and default route are "
                "present, but the gateway is unreachable."
            )
        }

    if not internet_reachable:
        return {
            "status": "PROBLEM",
            "severity": "HIGH",
            "finding": (
                "The gateway is reachable, but external "
                "network connectivity is unavailable."
            )
        }

    return {
        "status": "HEALTHY",
        "severity": "INFO",
        "finding": (
            "The network interface, default route, gateway, "
            "and external connectivity are all healthy."
        )
    }
