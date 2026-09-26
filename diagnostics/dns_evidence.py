from discovery.dns import discover_dns_servers

from dns_monitor import query_dns_server


def collect_dns_evidence(dns_target=None):
    """
    Collect one DNS evidence snapshot from the current machine.

    The snapshot contains:
        - discovered DNS servers
        - DNS query results for the requested target

    No infrastructure-specific DNS server values are hardcoded.
    """

    # ---------------------------------------------------------
    # 1. Discover DNS servers
    # ---------------------------------------------------------

    dns_servers = discover_dns_servers()

    # ---------------------------------------------------------
    # 2. Query discovered DNS servers
    # ---------------------------------------------------------

    dns_results = []

    if dns_target:
        for server in dns_servers:
            result = query_dns_server(
                server,
                dns_target
            )

            dns_results.append(result)

    # ---------------------------------------------------------
    # 3. Build DNS evidence snapshot
    # ---------------------------------------------------------

    return {
        "dns_target": dns_target,
        "dns_servers": dns_servers,
        "dns_results": dns_results
    }
