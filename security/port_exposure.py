
def analyze_service(service):
    address = service["address"]
    port = service["port"]
    protocol = service["protocol"]

    finding = {
        "protocol": protocol,
        "address": address,
        "port": port,
        "severity": "INFO",
        "exposure": "LOCAL",
        "message": ""
    }

    normalized_address = address

    # Remove IPv6 zone identifier if present.
    if "%" in normalized_address:
        normalized_address = normalized_address.split("%", 1)[0]

    # Remove IPv6 brackets.
    if (
        normalized_address.startswith("[")
        and normalized_address.endswith("]")
    ):
        normalized_address = normalized_address[1:-1]

    # IPv4 wildcard address.
    if normalized_address == "0.0.0.0":
        finding["severity"] = "WARNING"
        finding["exposure"] = "NETWORK"
        finding["message"] = (
            "Service is listening on all IPv4 interfaces."
        )

    # IPv6 wildcard address.
    elif normalized_address == "::":
        finding["severity"] = "WARNING"
        finding["exposure"] = "NETWORK"
        finding["message"] = (
            "Service is listening on all IPv6 interfaces."
        )

    # IPv4 localhost.
    elif normalized_address == "127.0.0.1":
        finding["severity"] = "INFO"
        finding["exposure"] = "LOCAL"
        finding["message"] = (
            "Service is listening only on IPv4 localhost."
        )

    # IPv6 localhost.
    elif normalized_address == "::1":
        finding["severity"] = "INFO"
        finding["exposure"] = "LOCAL"
        finding["message"] = (
            "Service is listening only on IPv6 localhost."
        )

    # Other specific addresses.
    else:
        finding["severity"] = "REVIEW"
        finding["exposure"] = "SPECIFIC_INTERFACE"
        finding["message"] = (
            "Service is listening on a specific network address."
        )

    return finding


def analyze_services(services):
    findings = []

    for service in services:
        finding = analyze_service(service)
        findings.append(finding)

    return findings
