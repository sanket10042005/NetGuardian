import socket
import subprocess
import time


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


def query_dns_server(dns_server, hostname):
    """
    Query a specific DNS server and return detailed DNS results.
    """

    result = {
        "dns_server": dns_server,
        "hostname": hostname,
        "status": "ERROR",
        "resolved": False,
        "ip_address": None,
        "response_time_ms": None
    }

    try:
        socket.inet_aton(dns_server)

    except OSError:
        return result

    try:
        start_time = time.perf_counter()

        query = subprocess.run(
            [
                "dig",
                f"@{dns_server}",
                hostname,
                "+noall",
                "+answer",
                "+comments",
                "+time=3",
                "+tries=1"
            ],
            capture_output=True,
            text=True,
            timeout=5
        )

        end_time = time.perf_counter()

        result["response_time_ms"] = round(
            (end_time - start_time) * 1000,
            2
        )

        output = query.stdout

        if "connection timed out" in output.lower():
            result["status"] = "TIMEOUT"
            return result

        if "status: SERVFAIL" in output:
            result["status"] = "SERVFAIL"
            return result

        if "status: NXDOMAIN" in output:
            result["status"] = "NXDOMAIN"
            return result

        if "status: NOERROR" in output:
            result["status"] = "NOERROR"

        if query.returncode != 0:
            result["status"] = "ERROR"
            return result

        answers = []

        for line in output.splitlines():
            line = line.strip()

            if not line:
                continue

            if line.startswith(";"):
                continue

            parts = line.split()

            if len(parts) < 5:
                continue

            record_type = parts[-2]
            record_value = parts[-1]

            if record_type == "A":
                answers.append(record_value)

        if answers:
            result["resolved"] = True
            result["ip_address"] = answers[0]

        return result

    except subprocess.TimeoutExpired:
        result["status"] = "TIMEOUT"
        return result

    except OSError:
        result["status"] = "ERROR"
        return result


def get_dns_servers():
    try:
        result = subprocess.run(
            ["resolvectl", "status"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )

        dns_servers = []

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("Current DNS Server:"):
                server = line.split(":", 1)[1].strip()

                if server and server not in dns_servers:
                    dns_servers.append(server)

            elif line.startswith("DNS Servers:"):
                servers = line.split(":", 1)[1].strip().split()

                for server in servers:
                    if server not in dns_servers:
                        dns_servers.append(server)

        return dns_servers

    except (
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError
    ):
        return []

    except OSError:
        return []
