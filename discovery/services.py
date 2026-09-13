import subprocess


def discover_tcp_services():
    try:
        result = subprocess.run(
            ["ss", "-tln"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )

        services = []

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line or line.startswith("State"):
                continue

            parts = line.split()

            if len(parts) < 4:
                continue

            local_address = parts[3]

            if ":" not in local_address:
                continue

            address, port = local_address.rsplit(":", 1)

            if not port.isdigit():
                continue

            service = {
                "protocol": "TCP",
                "address": address,
                "port": int(port)
            }

            if service not in services:
                services.append(service)

        return services

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return []

    except OSError:
        return []
