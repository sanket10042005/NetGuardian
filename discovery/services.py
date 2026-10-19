import re
import subprocess


PROCESS_PATTERN = re.compile(
    r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+)'
)


def normalize_address(address):
    """
    Normalize an address reported by ss.

    Converts wildcard '*' into IPv4's unspecified address.
    """
    address = address.strip()

    if address == "*":
        return "0.0.0.0"

    return address


def parse_process_owners(line):
    """
    Extract process ownership information from an ss output line.

    A socket can have multiple associated processes. If ownership
    information is unavailable, return an empty list.

    Process names and PIDs are discovered from command output;
    they are never hardcoded.
    """
    owners = []

    for match in PROCESS_PATTERN.finditer(line):
        owner = {
            "process_name": match.group("name"),
            "pid": int(match.group("pid"))
        }

        if owner not in owners:
            owners.append(owner)

    return owners


def parse_tcp_services(output):
    """
    Parse listening TCP sockets from ss -ltnpH output.

    Preserve the existing protocol, address, and port fields.
    Add dynamically discovered process ownership information.
    """
    services = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        parts = line.split()

        # Expected fields:
        # State, Recv-Q, Send-Q, Local Address:Port,
        # Peer Address:Port, optional process information.
        if len(parts) < 5:
            continue

        if parts[0] != "LISTEN":
            continue

        local_address = parts[3]

        if ":" not in local_address:
            continue

        address, port = local_address.rsplit(":", 1)

        if not port.isdigit():
            continue

        port = int(port)

        if not 1 <= port <= 65535:
            continue

        address = normalize_address(address)
        owners = parse_process_owners(line)

        service = {
            "protocol": "TCP",
            "address": address,
            "port": port,
            "process_owners": owners,
            "ownership_status": (
                "AVAILABLE" if owners else "UNAVAILABLE"
            )
        }

        # Retain the original service fields while allowing
        # multiple process owners to be represented.
        if owners:
            service["process_name"] = owners[0]["process_name"]
            service["pid"] = owners[0]["pid"]
        else:
            service["process_name"] = None
            service["pid"] = None

        # Prevent duplicate socket records.
        if service not in services:
            services.append(service)

    return services


def discover_tcp_services():
    """
    Discover listening TCP services using ss.

    This function does not automatically request root privileges.
    Process ownership may therefore be unavailable for some sockets.
    """
    try:
        result = subprocess.run(
            ["ss", "-ltnpH"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )

        return parse_tcp_services(result.stdout)

    except (
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        OSError
    ):
        return []
