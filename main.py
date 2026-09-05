from system_monitor import get_system_metrics, get_system_info
from health import check_health, get_overall_health


def display_report(
    operating_system,
    os_version,
    hostname,
    cpu_usage,
    memory_usage,
    disk_usage,
    cpu_status,
    memory_status,
    disk_status,
    overall_status
):
    print("========== NetGuardian ==========")

    print("System Information")
    print("OS:", operating_system)
    print("Kernel:", os_version)
    print("Hostname:", hostname)

    print()
    print("Resource Usage")
    print("CPU Usage:", cpu_usage, "%", "-", cpu_status)
    print("Memory Usage:", memory_usage, "%", "-", memory_status)
    print("Disk Usage:", disk_usage, "%", "-", disk_status)

    print()
    print("Overall System Health:", overall_status)

    print("=================================")



cpu_usage, memory_usage, disk_usage = get_system_metrics()


operating_system, os_version, hostname = get_system_info()


cpu_status = check_health(cpu_usage)
memory_status = check_health(memory_usage)
disk_status = check_health(disk_usage)


overall_status = get_overall_health(
    [cpu_status, memory_status, disk_status]
)


display_report(
    operating_system,
    os_version,
    hostname,
    cpu_usage,
    memory_usage,
    disk_usage,
    cpu_status,
    memory_status,
    disk_status,
    overall_status
)
