def assess_service_security(service_finding, firewall_status):
    address = service_finding["address"]
    port = service_finding["port"]
    protocol = service_finding["protocol"]

    exposure = service_finding["exposure"]

    assessment = {
        "protocol": protocol,
        "address": address,
        "port": port,
        "exposure": exposure,
        "firewall_status": firewall_status,
        "severity": "INFO",
        "message": ""
    }

    if exposure == "NETWORK":

        if firewall_status in (
            "INACTIVE",
            "NO_RULES"
        ):
            assessment["severity"] = "HIGH"
            assessment["message"] = (
                "Service is listening on a network-wide "
                "address while no active firewall protection "
                "was detected."
            )

        elif firewall_status == "ACCESS_DENIED":
            assessment["severity"] = "REVIEW"
            assessment["message"] = (
                "Service is listening on a network-wide "
                "address, but firewall inspection requires "
                "elevated privileges."
            )

        elif firewall_status == "ERROR":
            assessment["severity"] = "REVIEW"
            assessment["message"] = (
                "Service is listening on a network-wide "
                "address, but firewall inspection failed."
            )

        elif firewall_status == "UNKNOWN":
            assessment["severity"] = "REVIEW"
            assessment["message"] = (
                "Service is listening on a network-wide "
                "address, but firewall state is unknown."
            )

        else:
            assessment["severity"] = "WARNING"
            assessment["message"] = (
                "Service is listening on a network-wide "
                "address. Review firewall and access controls."
            )

    elif exposure == "LOCAL":

        assessment["severity"] = "INFO"
        assessment["message"] = (
            "Service is listening only on localhost."
        )

    elif exposure == "SPECIFIC_INTERFACE":

        assessment["severity"] = "REVIEW"
        assessment["message"] = (
            "Service is listening on a specific network "
            "address. Review whether this exposure is required."
        )

    else:

        assessment["severity"] = "REVIEW"
        assessment["message"] = (
            "Service exposure could not be fully classified."
        )

    return assessment
