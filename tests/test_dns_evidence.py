from diagnostics.dns_evidence import (
    collect_dns_evidence
)


def test_dns_evidence_without_target():
    evidence = collect_dns_evidence()

    assert "dns_target" in evidence
    assert "dns_servers" in evidence
    assert "dns_results" in evidence

    assert evidence["dns_target"] is None
    assert isinstance(evidence["dns_servers"], list)
    assert isinstance(evidence["dns_results"], list)

    assert evidence["dns_results"] == []


def test_dns_evidence_with_target():
    evidence = collect_dns_evidence(
        "google.com"
    )

    assert evidence["dns_target"] == "google.com"

    assert isinstance(
        evidence["dns_servers"],
        list
    )

    assert isinstance(
        evidence["dns_results"],
        list
    )


def test_dns_result_structure():
    evidence = collect_dns_evidence(
        "google.com"
    )

    for result in evidence["dns_results"]:
        assert "dns_server" in result
        assert "hostname" in result
        assert "status" in result
        assert "resolved" in result
        assert "ip_address" in result
        assert "response_time_ms" in result

        assert result["hostname"] == "google.com"

        assert result["status"] in (
            "NOERROR",
            "NXDOMAIN",
            "SERVFAIL",
            "TIMEOUT",
            "ERROR"
        )

        assert isinstance(
            result["resolved"],
            bool
        )
