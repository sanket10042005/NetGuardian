import ipaddress


def is_successful_dns_result(result):
    """
    Determine whether a DNS result contains evidence
    of successful address resolution.
    """

    if not isinstance(result, dict):
        return False

    if result.get("status") != "NOERROR":
        return False

    if result.get("resolved") is not True:
        return False

    address = result.get("ip_address")

    if not isinstance(address, str) or not address.strip():
        return False

    try:
        ipaddress.ip_address(address)
    except ValueError:
        return False

    return True


def analyze_dns_root_cause(evidence):
    """
    Analyze collected DNS evidence and identify
    the most likely DNS condition.

    Returns:
        status
        severity
        failure_domain
        finding
        recommendation
        server_results
        successful_server_count
        failed_server_count
    """

    if not isinstance(evidence, dict):
        evidence = {}

    dns_target = evidence.get("dns_target")
    dns_servers = evidence.get("dns_servers", [])
    dns_results = evidence.get("dns_results", [])

    if not isinstance(dns_servers, list):
        dns_servers = []

    if not isinstance(dns_results, list):
        dns_results = []

    successful_servers = []
    failed_servers = []
    incomplete_results = []

    valid_statuses = {
        "NOERROR",
        "NXDOMAIN",
        "SERVFAIL",
        "TIMEOUT",
        "ERROR"
    }

    for result in dns_results:
        if not isinstance(result, dict):
            failed_servers.append(result)
            incomplete_results.append(result)
            continue

        if is_successful_dns_result(result):
            successful_servers.append(result)
        else:
            failed_servers.append(result)

            status = result.get("status")

            # Missing or unexpected statuses indicate
            # incomplete or unreliable diagnostic evidence.
            if status not in valid_statuses:
                incomplete_results.append(result)

            # NOERROR without a valid resolved IP is
            # inconsistent with our expected A-record result.
            elif status == "NOERROR":
                incomplete_results.append(result)

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

    # --------------------------------------------------
    # 1. Check whether DNS testing was requested
    # --------------------------------------------------

    if not isinstance(dns_target, str) or not dns_target.strip():
        return build_diagnosis(
            "REVIEW",
            "LOW",
            "DNS",
            "DNS resolution was not tested.",
            "Provide a hostname to perform DNS diagnostics."
        )

    # --------------------------------------------------
    # 2. Check DNS server discovery
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 3. Check query evidence
    # --------------------------------------------------

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

    if incomplete_results:
        return build_diagnosis(
            "REVIEW",
            "MEDIUM",
            "DNS_EVIDENCE",
            (
                "One or more DNS results are incomplete "
                "or contain unexpected data."
            ),
            (
                "Inspect the DNS query results and verify "
                "that each result includes a valid status "
                "and consistent resolution information."
            )
        )

    # --------------------------------------------------
    # 4. Successful resolution through all servers
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 5. Partial success
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 6. Analyze failures
    # --------------------------------------------------

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

    # --------------------------------------------------
    # 7. Other failures
    # --------------------------------------------------

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
