from diagnostics.dns_root_cause import analyze_dns_root_cause


def make_evidence(
    dns_target="example.com",
    dns_servers=None,
    dns_results=None
):
    if dns_servers is None:
        dns_servers = ["192.0.2.53"]

    if dns_results is None:
        dns_results = [
            {
                "dns_server": "192.0.2.53",
                "hostname": "example.com",
                "status": "NOERROR",
                "resolved": True,
                "ip_address": "192.0.2.10",
                "response_time_ms": 25.0
            }
        ]

    return {
        "dns_target": dns_target,
        "dns_servers": dns_servers,
        "dns_results": dns_results
    }


def test_successful_dns_resolution():
    result = analyze_dns_root_cause(make_evidence())

    assert result["status"] == "HEALTHY"
    assert result["severity"] == "INFO"
    assert result["failure_domain"] == "NONE"


def test_dns_target_not_provided():
    evidence = make_evidence(dns_target=None)

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["failure_domain"] == "DNS"


def test_no_dns_servers_discovered():
    evidence = make_evidence(
        dns_servers=[],
        dns_results=[]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["failure_domain"] == "DNS_CONFIGURATION"


def test_all_servers_return_nxdomain():
    evidence = make_evidence(
        dns_results=[
            {
                "dns_server": "192.0.2.53",
                "status": "NXDOMAIN",
                "resolved": False
            }
        ]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["failure_domain"] == "DNS_NAME"


def test_all_servers_return_servfail():
    evidence = make_evidence(
        dns_results=[
            {
                "dns_server": "192.0.2.53",
                "status": "SERVFAIL",
                "resolved": False
            }
        ]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "PROBLEM"
    assert result["severity"] == "HIGH"
    assert result["failure_domain"] == "DNS_SERVER"


def test_all_servers_timeout():
    evidence = make_evidence(
        dns_results=[
            {
                "dns_server": "192.0.2.53",
                "status": "TIMEOUT",
                "resolved": False
            }
        ]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["failure_domain"] == "DNS_CONNECTIVITY"
def test_noerror_without_ip_address():
    evidence = make_evidence(
        dns_results=[
            {
                "dns_server": "192.0.2.53",
                "status": "NOERROR",
                "resolved": False,
                "ip_address": None,
                "response_time_ms": 20.0
            }
        ]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["failure_domain"] == "DNS_EVIDENCE"
    assert result["successful_server_count"] == 0
    assert result["failed_server_count"] == 1


def test_invalid_resolved_ip_address():
    evidence = make_evidence(
        dns_results=[
            {
                "dns_server": "192.0.2.53",
                "status": "NOERROR",
                "resolved": True,
                "ip_address": "not-an-ip-address",
                "response_time_ms": 20.0
            }
        ]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["failure_domain"] == "DNS_EVIDENCE"
    assert result["successful_server_count"] == 0


def test_missing_dns_status():
    evidence = make_evidence(
        dns_results=[
            {
                "dns_server": "192.0.2.53",
                "resolved": False,
                "ip_address": None
            }
        ]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["failure_domain"] == "DNS_EVIDENCE"


def test_one_server_succeeds_and_another_fails():
    evidence = make_evidence(
        dns_servers=[
            "192.0.2.53",
            "192.0.2.54"
        ],
        dns_results=[
            {
                "dns_server": "192.0.2.53",
                "status": "NOERROR",
                "resolved": True,
                "ip_address": "192.0.2.10",
                "response_time_ms": 25.0
            },
            {
                "dns_server": "192.0.2.54",
                "status": "SERVFAIL",
                "resolved": False,
                "ip_address": None,
                "response_time_ms": 40.0
            }
        ]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "HEALTHY"
    assert result["failure_domain"] == "DNS_RELIABILITY"
    assert result["successful_server_count"] == 1
    assert result["failed_server_count"] == 1


def test_malformed_dns_result():
    evidence = make_evidence(
        dns_results=[
            None
        ]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["failure_domain"] == "DNS_EVIDENCE"
    assert result["successful_server_count"] == 0


def test_empty_dns_results():
    evidence = make_evidence(
        dns_results=[]
    )

    result = analyze_dns_root_cause(evidence)

    assert result["status"] == "REVIEW"
    assert result["successful_server_count"] == 0
    assert result["failed_server_count"] == 0
