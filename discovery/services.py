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
    """
    owners = []

    for match in PROCESS_PATTERN.finditer(line):
        owner = {
            "process_name": match.group("name"),
            "pid": int(match.group("pid")),
        }

        if owner not in owners:
            owners.append(owner)

    return owners


def parse_tcp_services(output):
    """
    Parse listening TCP sockets from ss -ltnpH output.

    Process ownership is collected when visible to the current user.
    Missing ownership information is reported without guessing why
    it is unavailable.
    """
    services = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        parts = line.split()

        # State, Recv-Q, Send-Q, Local Address:Port,
        # Peer Address:Port, and optional process information.
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

        ownership_available = bool(owners)

        service = {
            "protocol": "TCP",
            "address": address,
            "port": port,
            "process_owners": owners,
            "ownership_status": (
                "AVAILABLE" if ownership_available else "UNAVAILABLE"
            ),
            "ownership_source": "ss",
            "ownership_note": (
                "Process ownership was discovered."
                if ownership_available
                else (
                    "Process ownership could not be verified "
                    "with the current visibility."
                )
            ),
        }

        # Preserve the original single-owner fields for compatibility.
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

    Does not automatically request root privileges. Ownership
    information may be unavailable for some sockets.
    """
    try:
        result = subprocess.run(
            ["ss", "-ltnpH"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )

        return parse_tcp_services(result.stdout)

    except (
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        OSError,
    ):
        return []
