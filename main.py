from system_monitor import get_system_metrics
from health import check_health


cpu_usage, memory_usage, disk_usage = get_system_metrics()

cpu_status = check_health(cpu_usage)
memory_status = check_health(memory_usage)
disk_status = check_health(disk_usage)


print("========== NetGuardian ==========")
print("CPU Usage:", cpu_usage, "%", "-", cpu_status)
print("Memory Usage:", memory_usage, "%", "-", memory_status)
print("Disk Usage:", disk_usage, "%", "-", disk_status)
print("=================================")
