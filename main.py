import argparse
import time
from datetime import datetime

from config import MONITORING_INTERVAL, TOP_PROCESS_LIMIT

from health import check_health, get_overall_health

from discovery.dns import discover_dns_servers
from discovery.services import discover_tcp_services

from dns_monitor import query_dns_server

from port_monitor import check_port

from process_monitor import (
    get_processes,
    get_top_cpu_processes,
    get_top_memory_processes
)

from system_monitor import (
    get_system_metrics,
    get_system_info
)

from security.port_exposure import analyze_services

from security.security_assessment import (
    assess_service_security
)

from security.firewall_monitor import (
    discover_firewalls
)

from diagnostics.network_evidence import (
    collect_network_evidence
)

from diagnostics.root_cause import (
    analyze_root_cause
)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NetGuardian infrastructure monitoring and diagnostics"
    )

    parser.add_argument(
        "--dns-target",
        help="Hostname to use for DNS diagnostics"
    )

    parser.add_argument(
        "--network-target",
        help="Host to use for external network reachability diagnostics"
    )

    return parser.parse_args()


def display_system_report():
    cpu_usage, memory_usage, disk_usage = get_system_metrics()

    operating_system, os_version, hostname = get_system_info()

    metrics = {
        "cpu": {
            "value": cpu_usage,
            "status": check_health(cpu_usage)
        },
        "memory": {
            "value": memory_usage,
            "status": check_health(memory_usage)
        },
        "disk": {
            "value": disk_usage,
            "status": check_health(disk_usage)
        }
    }

    statuses = [
        metrics["cpu"]["status"],
        metrics["memory"]["status"],
        metrics["disk"]["status"]
    ]

    overall_health = get_overall_health(statuses)

    print()
    print("========== NetGuardian ==========")

    print(
        "Monitoring Time:",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    print()
    print("System Information")

    print("OS:", operating_system)
    print("Kernel:", os_version)
    print("Hostname:", hostname)

    print()
    print("Resource Usage")

    print(
        "CPU       :",
        f"{metrics['cpu']['value']:.1f}%",
        "-",
        metrics["cpu"]["status"]
    )

    print(
        "Memory    :",
        f"{metrics['memory']['value']:.1f}%",
        "-",
        metrics["memory"]["status"]
    )

    print(
        "Disk      :",
        f"{metrics['disk']['value']:.1f}%",
        "-",
        metrics["disk"]["status"]
    )

    print()
    print("Overall System Health:", overall_health)

    print("=================================")


def display_network_interfaces(evidence):
    interfaces = evidence["interfaces"]

    print()
    print("========== Network Discovery ==========")

    if not interfaces:
        print("No network interfaces detected.")

    for interface in interfaces:
        print()
        print("Interface:", interface["name"])

        if interface["is_up"]:
            print("Status: UP")
        else:
            print("Status: DOWN")

        print("MAC Address:", interface["mac_address"])
        print("MTU:", interface["mtu"])

        if interface["ipv4_addresses"]:
            print("IPv4 Addresses:")

            for address in interface["ipv4_addresses"]:
                print(
                    " -",
                    address["address"],
                    "/",
                    address["netmask"]
                )

        else:
            print("IPv4 Addresses: None")

        if interface["ipv6_addresses"]:
            print("IPv6 Addresses:")

            for address in interface["ipv6_addresses"]:
                print(
                    " -",
                    address["address"],
                    "/",
                    address["netmask"]
                )

        else:
            print("IPv6 Addresses: None")

    print()
    print("========================================")


def display_routing_table(evidence):
    routes = evidence["routes"]

    print()
    print("========== Routing Table ==========")

    if not routes:
        print("No routing information available.")

    else:
        for route in routes:
            print()
            print("Destination:", route["destination"])
            print("Gateway:", route["gateway"])
            print("Interface:", route["interface"])
            print("Source IP:", route["source_ip"])
            print("Protocol:", route["protocol"])
            print("Metric:", route["metric"])

    print()
    print("===================================")


def display_gateway_diagnostic(evidence):
    gateway = evidence["gateway"]
    reachable = evidence["gateway_reachable"]
    packet_loss = evidence["gateway_packet_loss"]
    latency = evidence["gateway_latency"]

    print()
    print("========== Gateway Diagnostics ==========")

    print("Gateway:", gateway)

    if gateway is None:
        print("Status: NOT DETECTED")

    elif reachable:
        print("Status: REACHABLE")
        print("Packet Loss:", packet_loss, "%")
        print("Average Latency:", latency, "ms")

    else:
        print("Status: UNREACHABLE")
        print("Packet Loss: Unknown")
        print("Average Latency: Unknown")

    print("==========================================")


def display_path_diagnostic(evidence):
    gateway = evidence["gateway"]
    default_route = evidence["default_route"]

    print()
    print("========== Path Diagnostics ==========")

    if gateway is None:
        print("Target: Not available")
        print("Status: NO DEFAULT GATEWAY")

    elif default_route is None:
        print("Target:", gateway)
        print("Status: ROUTE NOT FOUND")

    else:
        print("Target:", gateway)
        print("Destination:", gateway)
        print("Gateway:", None)
        print("Interface:", default_route["interface"])
        print("Source IP:", default_route["source_ip"])
        print("Path Type: DIRECT")

    print("=======================================")


def display_processes(processes, title):
    print()
    print(f"========== {title} ==========")

    if not processes:
        print("No process information available.")

    else:
        for process in processes:
            print(
                "PID:", process["pid"],
                "| Name:", process["name"],
                "| CPU:", process["cpu"], "%",
                "| Memory:", round(process["memory"], 2), "%"
            )

    print("========================================")


def display_dns_diagnostic(dns_target):
    dns_servers = discover_dns_servers()

    print()
    print("========== DNS Diagnostics ==========")

    if not dns_servers:
        print("DNS Servers: Not detected")
        print("Status: DNS CONFIGURATION NOT FOUND")

    elif not dns_target:
        print("Discovered DNS Servers:")

        for server in dns_servers:
            print(" -", server)

        print()
        print("Status: DNS TEST TARGET NOT PROVIDED")
        print()
        print(
            "Use --dns-target <hostname> "
            "to perform DNS resolution tests."
        )

    else:
        print("Discovered DNS Servers:")

        for server in dns_servers:
            print(" -", server)

        print()
        print("DNS Resolution Tests")
        print("Test Host:", dns_target)

        for server in dns_servers:
            result = query_dns_server(
                server,
                dns_target
            )

            print()
            print("DNS Server:", result["dns_server"])
            print("Status:", result["status"])

            if result["resolved"]:
                print("IP Address:", result["ip_address"])

            else:
                print("IP Address: Unknown")

            if result["response_time_ms"] is not None:
                print(
                    "Response Time:",
                    result["response_time_ms"],
                    "ms"
                )

    print("====================================")


def display_network_diagnostic(evidence):
    diagnosis = analyze_root_cause(
        evidence
    )

    print()
    print("========== Network Diagnostic Engine ==========")

    # ---------------------------------------------------------
    # Collected Evidence
    # ---------------------------------------------------------

    print()
    print("Collected Evidence")

    if evidence["interface_up"] is True:
        print("Interface: UP")

    elif evidence["interface_up"] is False:
        print("Interface: DOWN")

    else:
        print("Interface: UNKNOWN")

    if evidence["gateway_detected"]:
        print("Gateway: DETECTED")

    else:
        print("Gateway: NOT DETECTED")

    if evidence["gateway_reachable"]:
        print("Gateway Reachability: REACHABLE")

    else:
        print("Gateway Reachability: UNREACHABLE")

    if evidence["default_route_present"]:
        print("Default Route: PRESENT")

    else:
        print("Default Route: NOT PRESENT")

    if evidence["internet_reachable"] is None:
        print("External Connectivity: NOT TESTED")

    elif evidence["internet_reachable"]:
        print("External Connectivity: REACHABLE")

    else:
        print("External Connectivity: UNREACHABLE")

    # ---------------------------------------------------------
    # Gateway Details
    # ---------------------------------------------------------

    print()
    print("Gateway Details")

    print(
        "Gateway:",
        evidence["gateway"]
    )

    if evidence["gateway_reachable"]:
        print("Status: REACHABLE")

        print(
            "Packet Loss:",
            evidence["gateway_packet_loss"],
            "%"
        )

        print(
            "Latency:",
            evidence["gateway_latency"],
            "ms"
        )

    else:
        if evidence["gateway"] is None:
            print("Status: NOT DETECTED")
        else:
            print("Status: UNREACHABLE")

        print("Packet Loss: Unknown")
        print("Latency: Unknown")

    # ---------------------------------------------------------
    # Default Route
    # ---------------------------------------------------------

    print()
    print("Default Route")

    default_route = evidence["default_route"]

    if default_route is None:
        print("Status: NOT FOUND")

    else:
        print("Status: PRESENT")
        print(
            "Gateway:",
            default_route["gateway"]
        )
        print(
            "Interface:",
            default_route["interface"]
        )
        print(
            "Source IP:",
            default_route["source_ip"]
        )
        print(
            "Protocol:",
            default_route["protocol"]
        )
        print(
            "Metric:",
            default_route["metric"]
        )

    # ---------------------------------------------------------
    # External Connectivity
    # ---------------------------------------------------------

    print()
    print("External Connectivity")

    if evidence["network_target"] is None:
        print("Status: TEST NOT PERFORMED")

        print()
        print(
            "Use --network-target <host> "
            "to perform external connectivity diagnostics."
        )

    else:
        print(
            "Target:",
            evidence["network_target"]
        )

        if evidence["internet_reachable"]:
            print("Status: REACHABLE")

            print(
                "Packet Loss:",
                evidence["internet_packet_loss"],
                "%"
            )

            print(
                "Latency:",
                evidence["internet_latency"],
                "ms"
            )

        else:
            print("Status: UNREACHABLE")

            print(
                "Packet Loss:",
                evidence["internet_packet_loss"]
            )

            print(
                "Latency:",
                evidence["internet_latency"]
            )

    # ---------------------------------------------------------
    # Root-Cause Analysis
    # ---------------------------------------------------------

    print()
    print("Root-Cause Analysis")

    print(
        "Status:",
        diagnosis["status"]
    )

    print(
        "Severity:",
        diagnosis["severity"]
    )

    print(
        "Failure Domain:",
        diagnosis["failure_domain"]
    )

    print(
        "Finding:",
        diagnosis["finding"]
    )

    print(
        "Recommendation:",
        diagnosis["recommendation"]
    )

    print()
    print("==============================================")


def display_service_discovery(services):
    print()
    print("========== Service Discovery ==========")

    if not services:
        print("No TCP listening services detected.")

    else:
        for service in services:
            print(
                service["protocol"],
                service["address"],
                ":",
                service["port"]
            )

    print("========================================")


def display_port_diagnostic(services):
    print()
    print("========== Port Diagnostics ==========")

    if not services:
        print("No TCP listening ports detected.")

    else:
        print("Testing discovered TCP services:")

        for service in services:
            address = service["address"]
            port = service["port"]

            test_address = address

            if "%" in test_address:
                test_address = test_address.split("%", 1)[0]

            if (
                test_address.startswith("[")
                and test_address.endswith("]")
            ):
                test_address = test_address[1:-1]

            if test_address == "0.0.0.0":
                test_address = "127.0.0.1"

            elif test_address == "::":
                test_address = "::1"

            result = check_port(
                test_address,
                port
            )

            print()
            print("Address:", address)
            print("Port:", port)
            print("Protocol:", service["protocol"])
            print("Test Address:", test_address)

            if result["open"]:
                print("Status: OPEN")

            else:
                print("Status: CLOSED")

    print("======================================")


def display_security_diagnostic(services):
    firewall_data = discover_firewalls()

    findings = analyze_services(services)

    print()
    print("========== Security Assessment ==========")

    if not findings:
        print("No TCP services available for security analysis.")

    else:
        firewall_statuses = []

        for firewall in firewall_data.values():

            if firewall["status"] == "ACTIVE":
                firewall_statuses.append("ACTIVE")

            elif firewall["status"] == "RULES_PRESENT":
                firewall_statuses.append("ACTIVE")

        if firewall_statuses:
            firewall_status = "ACTIVE"

        elif any(
            firewall["status"] == "ACCESS_DENIED"
            for firewall in firewall_data.values()
        ):
            firewall_status = "ACCESS_DENIED"

        elif any(
            firewall["status"] == "INACTIVE"
            for firewall in firewall_data.values()
        ):
            firewall_status = "INACTIVE"

        elif any(
            firewall["status"] == "NO_RULES"
            for firewall in firewall_data.values()
        ):
            firewall_status = "NO_RULES"

        else:
            firewall_status = "UNKNOWN"

        print()
        print("Firewall Assessment:", firewall_status)

        for finding in findings:

            assessment = assess_service_security(
                finding,
                firewall_status
            )

            print()
            print("Protocol:", assessment["protocol"])
            print("Address:", assessment["address"])
            print("Port:", assessment["port"])
            print("Exposure:", assessment["exposure"])
            print(
                "Firewall Status:",
                assessment["firewall_status"]
            )
            print("Severity:", assessment["severity"])
            print("Finding:", assessment["message"])

    print("==========================================")


def collect_and_display(
    dns_target,
    network_target
):
    # ---------------------------------------------------------
    # System information
    # ---------------------------------------------------------

    display_system_report()

    # ---------------------------------------------------------
    # ONE network evidence snapshot
    # ---------------------------------------------------------

    network_evidence = collect_network_evidence(
        network_target
    )

    # ---------------------------------------------------------
    # All network displays consume the same snapshot
    # ---------------------------------------------------------

    display_network_interfaces(
        network_evidence
    )

    display_routing_table(
        network_evidence
    )

    display_path_diagnostic(
        network_evidence
    )

    display_gateway_diagnostic(
        network_evidence
    )

    # ---------------------------------------------------------
    # Process monitoring
    # ---------------------------------------------------------

    processes = get_processes()

    top_cpu = get_top_cpu_processes(
        processes,
        limit=TOP_PROCESS_LIMIT
    )

    top_memory = get_top_memory_processes(
        processes,
        limit=TOP_PROCESS_LIMIT
    )

    display_processes(
        top_cpu,
        "Top CPU Processes"
    )

    display_processes(
        top_memory,
        "Top Memory Processes"
    )

    # ---------------------------------------------------------
    # DNS diagnostics
    # ---------------------------------------------------------

    display_dns_diagnostic(
        dns_target
    )

    # ---------------------------------------------------------
    # Network diagnostic engine
    # Uses the SAME network evidence snapshot
    # ---------------------------------------------------------

    display_network_diagnostic(
        network_evidence
    )

    # ---------------------------------------------------------
    # Service and security diagnostics
    # ---------------------------------------------------------

    services = discover_tcp_services()

    display_service_discovery(
        services
    )

    display_port_diagnostic(
        services
    )

    display_security_diagnostic(
        services
    )


def main():
    args = parse_arguments()

    print("Starting NetGuardian monitoring...")
    print("Press Ctrl+C to stop monitoring.")

    if args.dns_target:
        print(
            "DNS test target:",
            args.dns_target
        )

    if args.network_target:
        print(
            "Network test target:",
            args.network_target
        )

    try:
        while True:
            collect_and_display(
                args.dns_target,
                args.network_target
            )

            print()
            print(
                f"Next check in "
                f"{MONITORING_INTERVAL} seconds..."
            )

            time.sleep(
                MONITORING_INTERVAL
            )

    except KeyboardInterrupt:
        print()
        print("Stopping NetGuardian...")
        print("Monitoring stopped safely.")


if __name__ == "__main__":
    main()
