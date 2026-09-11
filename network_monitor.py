import re
import subprocess


def ping_host(host, count=4):
    command = [
        "ping",
        "-c",
        str(count),
        host
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                "host": host,
                "reachable": False,
                "packet_loss": None,
                "latency": None
            }

        output = result.stdout

        packet_loss = parse_packet_loss(output)
        latency = parse_average_latency(output)

        return {
            "host": host,
            "reachable": True,
            "packet_loss": packet_loss,
            "latency": latency
        }

    except subprocess.TimeoutExpired:
        return {
            "host": host,
            "reachable": False,
            "packet_loss": None,
            "latency": None
        }

    except Exception:
        return {
            "host": host,
            "reachable": False,
            "packet_loss": None,
            "latency": None
        }


def parse_packet_loss(output):
    match = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)

    if match:
        return float(match.group(1))

    return None


def parse_average_latency(output):
    match = re.search(
        r"rtt min/avg/max/mdev = "
        r"[\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms",
        output
    )

    if match:
        return float(match.group(1))

    return None
