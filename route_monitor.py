import subprocess


def get_routing_table():
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )

        return result.stdout

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return None

    except OSError:
        return None


def parse_routing_table(output):
    routes = []

    if not output:
        return routes

    for line in output.splitlines():
        parts = line.split()

        if not parts:
            continue

        route = {
            "destination": parts[0],
            "gateway": None,
            "interface": None,
            "source_ip": None,
            "protocol": None,
            "metric": None
        }

        index = 1

        while index < len(parts):
            if parts[index] == "via":
                route["gateway"] = parts[index + 1]

            elif parts[index] == "dev":
                route["interface"] = parts[index + 1]

            elif parts[index] == "src":
                route["source_ip"] = parts[index + 1]

            elif parts[index] == "proto":
                route["protocol"] = parts[index + 1]

            elif parts[index] == "metric":
                route["metric"] = int(parts[index + 1])

            index += 1

        routes.append(route)

    return routes
