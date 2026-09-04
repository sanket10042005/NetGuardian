import psutil

def check_health(value):
    if value < 70:
        return "HEALTHY"
    elif value <= 90:
        return "WARNING"
    else:
        return "CRITICAL"

cpu_usage = psutil.cpu_percent(interval=1)
memory_usage = psutil.virtual_memory().percent
disk_usage = psutil.disk_usage("/").percent

cpu_status = check_health(cpu_usage)
memory_status = check_health(memory_usage)
disk_status = check_health(disk_usage)


print("========== NetGuardian ==========")
print("CPU Usage:", cpu_usage, "%", "-", cpu_status)
print("Memory Usage:", memory_usage, "%", "-", memory_status)
print("Disk Usage:", disk_usage, "%", "-", disk_status)
print("=================================")


