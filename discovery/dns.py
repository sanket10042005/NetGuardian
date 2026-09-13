import subprocess


def discover_dns_servers():
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

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return []

    except OSError:
        return []
