import subprocess

from network_monitor import ping_host


def get_default_gateway():
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )

        for line in result.stdout.splitlines():
            parts = line.split()

            if len(parts) >= 3 and parts[0] == "default":
                return parts[2]

        return None

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return None

    except OSError:
        return None


def check_gateway():
    gateway = get_default_gateway()

    if gateway is None:
        return {
            "gateway": None,
            "reachable": False,
            "packet_loss": None,
            "latency": None
        }

    result = ping_host(gateway)

    return {
        "gateway": gateway,
        "reachable": result["reachable"],
        "packet_loss": result["packet_loss"],
        "latency": result["latency"]
    }
