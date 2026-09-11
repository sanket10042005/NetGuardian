import socket


def resolve_hostname(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)

        return {
            "hostname": hostname,
            "resolved": True,
            "ip_address": ip_address
        }

    except socket.gaierror:
        return {
            "hostname": hostname,
            "resolved": False,
            "ip_address": None
        }

    except Exception:
        return {
            "hostname": hostname,
            "resolved": False,
            "ip_address": None
        }
