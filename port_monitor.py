import socket
import subprocess


def get_socket_family(host):
    try:
        socket.inet_pton(socket.AF_INET, host)
        return socket.AF_INET

    except OSError:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, host)
        return socket.AF_INET6

    except OSError:
        return socket.AF_UNSPEC


def check_port(host, port, timeout=3):
    family = get_socket_family(host)

    if family == socket.AF_UNSPEC:
        return {
            "host": host,
            "port": port,
            "open": False
        }

    try:
        with socket.socket(
            family,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            if family == socket.AF_INET6:
                result = sock.connect_ex((host, port, 0, 0))

            else:
                result = sock.connect_ex((host, port))

            if result == 0:
                return {
                    "host": host,
                    "port": port,
                    "open": True
                }

            return {
                "host": host,
                "port": port,
                "open": False
            }

    except socket.timeout:
        return {
            "host": host,
            "port": port,
            "open": False
        }

    except OSError:
        return {
            "host": host,
            "port": port,
            "open": False
        }


def get_listening_ports():
    try:
        result = subprocess.run(
            ["ss", "-tln"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )

        ports = []

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

            port = local_address.rsplit(":", 1)[1]

            if port.isdigit():
                port = int(port)

                if port not in ports:
                    ports.append(port)

        return sorted(ports)

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return []

    except OSError:
        return []
