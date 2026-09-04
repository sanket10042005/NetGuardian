import psutil

cpu_usage = psutil.cpu_percent(interval=1)
memory_usage = psutil.virtual_memory().percent
disk_usage = psutil.disk_usage("/").percent

print("========= NetGuardian ================")
print("CPU Usage:",cpu_usage, "%")
print("Memory Usage:", memory_usage, "%")
print("Disk Usage:", disk_usage, "%")
print(" =====================================")
