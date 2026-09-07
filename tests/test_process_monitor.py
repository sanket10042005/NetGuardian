from process_monitor import (
    get_top_cpu_processes,
    get_top_memory_processes
)


def test_top_cpu_processes():
    processes = [
        {"pid": 1, "name": "process1", "cpu": 10.0, "memory": 2.0},
        {"pid": 2, "name": "process2", "cpu": 50.0, "memory": 1.0},
        {"pid": 3, "name": "process3", "cpu": 30.0, "memory": 3.0}
    ]

    result = get_top_cpu_processes(processes, limit=2)

    assert result[0]["pid"] == 2
    assert result[1]["pid"] == 3


def test_top_memory_processes():
    processes = [
        {"pid": 1, "name": "process1", "cpu": 10.0, "memory": 2.0},
        {"pid": 2, "name": "process2", "cpu": 50.0, "memory": 1.0},
        {"pid": 3, "name": "process3", "cpu": 30.0, "memory": 3.0}
    ]

    result = get_top_memory_processes(processes, limit=2)

    assert result[0]["pid"] == 3
    assert result[1]["pid"] == 1
