import time
from datetime import datetime

from health import check_health, get_overall_health
from dns_monitor import resolve_hostname
from network_monitor import ping_host
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
        "Cpu       :",
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


def display_processes(processes, title):
    print()
    print(f"========== {title} ==========")

    for process in processes:
        print(
            "PID:", process["pid"],
            "| Name:", process["name"],
            "| CPU:", process["cpu"], "%",
            "| Memory:", round(process["memory"], 2), "%"
        )

    print("========================================")


def display_dns_diagnostic():
    result = resolve_hostname("google.com")

    print()
    print("========== DNS Diagnostics ==========")
    print("Hostname:", result["hostname"])

    if result["resolved"]:
        print("Status: RESOLVED")
        print("IP Address:", result["ip_address"])
    else:
        print("Status: NOT RESOLVED")
        print("IP Address: Unknown")

    print("======================================")


def display_network_diagnostic():
    result = ping_host("8.8.8.8")

    print()
    print("========== Network Diagnostics ==========")
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


def display_port_diagnostic():
    result = check_port("8.8.8.8", 53)

    print()
    print("========== Port Diagnostics ==========")
    print("Target:", result["host"])
    print("Port:", result["port"])
    print("Protocol: TCP")

    if result["open"]:
        print("Status: OPEN")
    else:
        print("Status: CLOSED")

    print("======================================")


def collect_and_display():
    display_system_report()

    processes = get_processes()

    top_cpu = get_top_cpu_processes(
        processes,
        limit=5
    )

    top_memory = get_top_memory_processes(
        processes,
        limit=5
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

    display_port_diagnostic()


print("Starting NetGuardian monitoring...")
print("Press Ctrl+C to stop monitoring.")

try:
    while True:
        collect_and_display()

        print()
        print("Next check in 5 seconds...")
        time.sleep(5)

except KeyboardInterrupt:
    print()
    print("Stopping NetGuardian...")
    print("Monitoring stopped safely.")
