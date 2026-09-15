
import time
from datetime import datetime

from config import MONITORING_INTERVAL, TOP_PROCESS_LIMIT

from health import check_health, get_overall_health

from discovery.network import discover_network_interfaces
from discovery.dns import discover_dns_servers
from discovery.services import discover_tcp_services

from dns_monitor import resolve_hostname

from gateway_monitor import (
    check_gateway,
    get_default_gateway
)

from network_monitor import ping_host

from port_monitor import check_port

from route_monitor import (
    get_routing_table,
    parse_routing_table
)

from path_monitor import (
    get_route_to_host,
    parse_route
)

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


def display_network_interfaces():
    interfaces = discover_network_interfaces()

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


def display_routing_table():
    output = get_routing_table()
    routes = parse_routing_table(output)

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


def display_gateway_diagnostic():
    result = check_gateway()

    print()
    print("========== Gateway Diagnostics ==========")

    print("Gateway:", result["gateway"])

    if result["gateway"] is None:
        print("Status: NOT DETECTED")

    elif result["reachable"]:
        print("Status: REACHABLE")
        print("Packet Loss:", result["packet_loss"], "%")
        print("Average Latency:", result["latency"], "ms")

    else:
        print("Status: UNREACHABLE")
        print("Packet Loss: Unknown")
        print("Average Latency: Unknown")

    print("==========================================")


def display_path_diagnostic():
    gateway = get_default_gateway()

    print()
    print("========== Path Diagnostics ==========")

    if gateway is None:
        print("Target: Not available")
        print("Status: NO DEFAULT GATEWAY")

    else:
        output = get_route_to_host(gateway)
        route = parse_route(output)

        print("Target:", gateway)

        if route is None:
            print("Status: ROUTE NOT FOUND")

        else:
            print("Destination:", route["destination"])
            print("Gateway:", route["gateway"])
            print("Interface:", route["interface"])
            print("Source IP:", route["source_ip"])

            if route["gateway"] is None:
                print("Path Type: DIRECT")

            else:
                print("Path Type: VIA GATEWAY")

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


def display_dns_diagnostic():
    dns_servers = discover_dns_servers()

    print()
    print("========== DNS Discovery ==========")

    if not dns_servers:
        print("DNS Servers: Not detected")
        print("Status: DNS CONFIGURATION NOT FOUND")

    else:
        print("DNS Servers:")

        for server in dns_servers:
            print(" -", server)

        hostname = get_system_info()[2]

        result = resolve_hostname(hostname)

        print()
        print("Resolution Test Host:", hostname)

        if result["resolved"]:
            print("Status: RESOLVED")
            print("IP Address:", result["ip_address"])

        else:
            print("Status: NOT RESOLVED")
            print("IP Address: Unknown")

    print("==================================")


def display_network_diagnostic():
    gateway = get_default_gateway()

    print()
    print("========== Network Diagnostics ==========")

    if gateway is None:
        print("Target: Not available")
        print("Status: NO DEFAULT GATEWAY")

    else:
        result = ping_host(gateway)

        print("Target:", result["host"])

        if result["reachable"]:
            print("Status: REACHABLE")
            print("Packet Loss:", result["packet_loss"], "%")
            print("Average Latency:", result["latency"], "ms")

        else:
            print("Status: UNREACHABLE")
            print("Packet Loss: Unknown")
            print("Average Latency: Unknown")

    print("==========================================")


def display_service_discovery():
    services = discover_tcp_services()

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


def display_port_diagnostic():
    services = discover_tcp_services()

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


def display_security_diagnostic():
    services = discover_tcp_services()

    findings = analyze_services(services)

    print()
    print("========== Security Diagnostics ==========")

    if not findings:
        print("No TCP services available for security analysis.")

    else:
        for finding in findings:
            print()
            print("Address:", finding["address"])
            print("Port:", finding["port"])
            print("Protocol:", finding["protocol"])
            print("Severity:", finding["severity"])
            print("Exposure:", finding["exposure"])
            print("Finding:", finding["message"])

    print("==========================================")


def collect_and_display():
    display_system_report()

    display_network_interfaces()

    display_routing_table()

    display_path_diagnostic()

    display_gateway_diagnostic()

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

    display_dns_diagnostic()

    display_network_diagnostic()

    display_service_discovery()

    display_port_diagnostic()

    display_security_diagnostic()


def main():
    print("Starting NetGuardian monitoring...")
    print("Press Ctrl+C to stop monitoring.")

    try:
        while True:
            collect_and_display()

            print()
            print(
                f"Next check in "
                f"{MONITORING_INTERVAL} seconds..."
            )

            time.sleep(MONITORING_INTERVAL)

    except KeyboardInterrupt:
        print()
        print("Stopping NetGuardian...")
        print("Monitoring stopped safely.")


if __name__ == "__main__":
    main()
