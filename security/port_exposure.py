import ipaddress


def normalize_address(address):
    address = address.strip()

    if address == "*":
        return "0.0.0.0"

    if "%" in address:
        address = address.split("%", 1)[0]

    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]

    return address






















def classify_exposure(address):
    """
    Classify network exposure based on the IP address.

    Returns:
        LOCAL
        NETWORK
        SPECIFIC_INTERFACE
        UNKNOWN
    """

    normalized_address = normalize_address(address)

    try:
        ip = ipaddress.ip_address(normalized_address)

    except ValueError:
        return "UNKNOWN"

    if ip.is_loopback:
        return "LOCAL"

    if ip.is_unspecified:
        return "NETWORK"

    return "SPECIFIC_INTERFACE"


def analyze_service(service):
    address = service["address"]
    port = service["port"]
    protocol = service["protocol"]

    exposure = classify_exposure(address)

    finding = {
        "protocol": protocol,
        "address": address,
        "port": port,
        "severity": "INFO",
        "exposure": exposure,
        "message": ""
    }

    if exposure == "NETWORK":
        finding["severity"] = "WARNING"
        finding["message"] = (
            "Service is listening on a network-wide address."
        )

    elif exposure == "LOCAL":
        finding["severity"] = "INFO"
        finding["message"] = (
            "Service is listening only on a local loopback address."
        )

    elif exposure == "SPECIFIC_INTERFACE":
        finding["severity"] = "REVIEW"
        finding["message"] = (
            "Service is listening on a specific network address. "
            "Review whether this exposure is required."
        )

    else:
        finding["severity"] = "REVIEW"
        finding["message"] = (
            "Service address could not be classified."
        )

    return finding


def analyze_services(services):
    findings = []

    for service in services:
        finding = analyze_service(service)
        findings.append(finding)

    return findings
