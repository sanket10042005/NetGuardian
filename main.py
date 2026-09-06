import time
from datetime import datetime

from system_monitor import get_system_metrics, get_system_info
from health import check_health, get_overall_health


def display_report(system_info, metrics):
    print()
    print("========== NetGuardian ==========")

    print("Monitoring Time:", system_info["timestamp"])

    print()
    print("System Information")
    print("OS:", system_info["os"])
    print("Kernel:", system_info["kernel"])
    print("Hostname:", system_info["hostname"])

    print()
    print("Resource Usage")

    for name, data in metrics.items():
        print(
            f"{name.capitalize():<10}: "
            f"{data['value']}% - {data['status']}"
        )

    statuses = [data["status"] for data in metrics.values()]
    overall_status = get_overall_health(statuses)

    print()
    print("Overall System Health:", overall_status)
    print("=================================")


def collect_and_display():
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

    system_info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "os": operating_system,
        "kernel": os_version,
        "hostname": hostname
    }

    display_report(system_info, metrics)


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
