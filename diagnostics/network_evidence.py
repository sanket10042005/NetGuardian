from discovery.network import discover_network_interfaces

from gateway_monitor import check_gateway

from route_monitor import (
    get_routing_table,
    parse_routing_table
)

from path_monitor import (
    get_route_to_host,
    parse_route
)

from network_monitor import ping_host


def collect_network_evidence(network_target=None):
    """
    Collect one network evidence snapshot from the current machine.

    The snapshot contains both:
        - summarized evidence for root-cause analysis
        - detailed evidence for reporting

    No infrastructure-specific values are hardcoded.
    """

    # ---------------------------------------------------------
    # 1. Discover network interfaces
    # ---------------------------------------------------------

    interfaces = discover_network_interfaces()

    # ---------------------------------------------------------
    # 2. Discover and test the default gateway
    # ---------------------------------------------------------

    gateway_result = check_gateway()

    # ---------------------------------------------------------
    # 3. Discover routing table
    # ---------------------------------------------------------

    routing_output = get_routing_table()
    routes = parse_routing_table(routing_output)

    default_route = next(
        (
            route
            for route in routes
            if route.get("destination") == "default"
        ),
        None
    )

    # ---------------------------------------------------------
    # 4. Determine whether the interface used by the
    #    default route is currently up
    # ---------------------------------------------------------

    interface_up = None

    if default_route is not None:
        route_interface = default_route.get("interface")

        interface_up = any(
            interface["name"] == route_interface
            and interface["is_up"]
            for interface in interfaces
        )

    # ---------------------------------------------------------
    # 5. Discover the route to the requested network target
    # ---------------------------------------------------------

    target_route = None

    if network_target:
        target_route_output = get_route_to_host(
            network_target
        )

        target_route = parse_route(
            target_route_output
        )

    # ---------------------------------------------------------
    # 6. Optional external connectivity test
    # ---------------------------------------------------------

    internet_result = None

    if network_target:
        internet_result = ping_host(
            network_target
        )

    # ---------------------------------------------------------
    # 7. Build one complete evidence snapshot
    # ---------------------------------------------------------

    return {
        # Detailed evidence
        "interfaces": interfaces,

        "gateway": gateway_result["gateway"],
        "gateway_packet_loss": gateway_result["packet_loss"],
        "gateway_latency": gateway_result["latency"],

        "routes": routes,
        "default_route": default_route,

        "network_target": network_target,
        "target_route": target_route,

        "internet_packet_loss": (
            internet_result["packet_loss"]
            if internet_result is not None
            else None
        ),

        "internet_latency": (
            internet_result["latency"]
            if internet_result is not None
            else None
        ),

        # Root-cause summary evidence
        "interface_up": interface_up,

        "gateway_detected": (
            gateway_result["gateway"] is not None
        ),

        "gateway_reachable": gateway_result["reachable"],

        "default_route_present": (
            default_route is not None
        ),

        "internet_reachable": (
            internet_result["reachable"]
            if internet_result is not None
            else None
        )
    }
