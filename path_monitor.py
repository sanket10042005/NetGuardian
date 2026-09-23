import subprocess


def get_route_to_host(host):
    try:
        result = subprocess.run(
            ["ip", "route", "get", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )

        return result.stdout.strip()

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return None

    except OSError:
        return None


def parse_route(output):
    if not output:
        return None

    parts = output.split()

    if not parts:
        return None

    route = {
        "destination": parts[0],
        "gateway": None,
        "interface": None,
        "source_ip": None
    }

    index = 1

    while index < len(parts):
        if parts[index] == "via":
            if index + 1 < len(parts):
                route["gateway"] = parts[index + 1]

        elif parts[index] == "dev":
            if index + 1 < len(parts):
                route["interface"] = parts[index + 1]

        elif parts[index] == "src":
            if index + 1 < len(parts):
                route["source_ip"] = parts[index + 1]

        index += 1

    return route
