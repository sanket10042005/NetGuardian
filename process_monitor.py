import psutil
import time


def get_processes():
    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "memory_percent"]
    ):
        try:
            process.cpu_percent(interval=None)
            processes.append(process)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(1)

    process_data = []

    for process in processes:
        try:
            name = process.name()

            if not name:
                name = "Unknown"

            process_data.append({
                "pid": process.pid,
                "name": name,
                "cpu": process.cpu_percent(interval=None),
                "memory": process.memory_percent()
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return process_data


def get_top_cpu_processes(processes, limit=10):
    return sorted(
        processes,
        key=lambda process: process["cpu"],
        reverse=True
    )[:limit]


def get_top_memory_processes(processes, limit=10):
    return sorted(
        processes,
        key=lambda process: process["memory"],
        reverse=True
    )[:limit]


def display_processes(processes, title, limit=10):
    print()
    print(f"========== {title} ==========")

    for process in processes[:limit]:
        print(
            "PID:", process["pid"],
            "| Name:", process["name"],
            "| CPU:", process["cpu"], "%",
            "| Memory:", round(process["memory"], 2), "%"
        )

    print("========================================")
