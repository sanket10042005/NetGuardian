import socket


def check_port(host, port, timeout=3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

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
