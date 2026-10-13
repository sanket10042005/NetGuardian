def analyze_dns_root_cause(evidence):
    """
    Analyze collected DNS evidence and identify
    the most likely DNS condition.

    Returns a structured diagnostic result with:
        status
        severity
        failure_domain
        finding
        recommendation
        server_results
        successful_server_count
        failed_server_count
    """

    dns_target = evidence.get("dns_target")
    dns_servers = evidence.get("dns_servers", [])
    dns_results = evidence.get("dns_results", [])

    successful_servers = [
        result
        for result in dns_results
        if (
            result.get("status") == "NOERROR"
            and result.get("resolved") is True
        )
    ]

    failed_servers = [
        result
        for result in dns_results
        if not (
            result.get("status") == "NOERROR"
            and result.get("resolved") is True
        )
    ]

    successful_count = len(successful_servers)
    failed_count = len(failed_servers)

    def build_diagnosis(
        status,
        severity,
        failure_domain,
        finding,
        recommendation
    ):
        return {
            "status": status,
            "severity": severity,
            "failure_domain": failure_domain,
            "finding": finding,
            "recommendation": recommendation,
            "server_results": dns_results,
            "successful_server_count": successful_count,
            "failed_server_count": failed_count
        }

    if not dns_target:
        return build_diagnosis(
            "REVIEW",
            "LOW",
            "DNS",
            "DNS resolution was not tested.",
            "Provide a hostname to perform DNS diagnostics."
        )

    if not dns_servers:
        return build_diagnosis(
            "REVIEW",
            "MEDIUM",
            "DNS_CONFIGURATION",
            "No DNS servers were discovered.",
            (
                "Inspect the host's DNS configuration and "
                "verify that DNS servers are available."
            )
        )

    if not dns_results:
        return build_diagnosis(
            "REVIEW",
            "MEDIUM",
            "DNS",
            "No DNS query results are available.",
            (
                "Verify DNS query execution and inspect "
                "the diagnostic output for errors."
            )
        )

    if successful_count > 0 and failed_count == 0:
        return build_diagnosis(
            "HEALTHY",
            "INFO",
            "NONE",
            f"DNS resolution succeeded for {dns_target}.",
            (
                "No corrective action is required based "
                "on the collected DNS evidence."
            )
        )

    if successful_count > 0 and failed_count > 0:
        return build_diagnosis(
            "HEALTHY",
            "INFO",
            "DNS_RELIABILITY",
            (
                "DNS resolution succeeded through at least "
                "one server, but other DNS servers failed."
            ),
            (
                "Inspect the failed DNS servers and compare "
                "their response statuses and response times."
            )
        )

    statuses = [
        result.get("status")
        for result in dns_results
    ]

    if all(status == "NXDOMAIN" for status in statuses):
        return build_diagnosis(
            "REVIEW",
            "MEDIUM",
            "DNS_NAME",
            (
                f"All queried DNS servers returned NXDOMAIN "
                f"for {dns_target}."
            ),
            (
                "Verify the hostname spelling and confirm "
                "that the requested DNS record exists."
            )
        )

    if all(status == "SERVFAIL" for status in statuses):
        return build_diagnosis(
            "PROBLEM",
            "HIGH",
            "DNS_SERVER",
            "All queried DNS servers returned SERVFAIL.",
            (
                "Investigate DNS server-side resolution, "
                "upstream DNS dependencies, and server health."
            )
        )

    if all(status == "TIMEOUT" for status in statuses):
        return build_diagnosis(
            "REVIEW",
            "MEDIUM",
            "DNS_CONNECTIVITY",
            "All queried DNS servers timed out.",
            (
                "Check DNS server reachability, network "
                "connectivity, and firewall rules affecting "
                "DNS traffic."
            )
        )

    return build_diagnosis(
        "REVIEW",
        "MEDIUM",
        "DNS",
        (
            "DNS resolution failed, but the available "
            "evidence does not identify one definitive cause."
        ),
        (
            "Inspect individual DNS server results and "
            "investigate the reported response statuses."
        )
    )
