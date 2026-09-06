from health import check_health, get_overall_health


def test_check_health():
    assert check_health(69) == "HEALTHY"
    assert check_health(70) == "WARNING"
    assert check_health(90) == "WARNING"
    assert check_health(91) == "CRITICAL"


def test_overall_health():
    assert get_overall_health(
        ["HEALTHY", "HEALTHY", "HEALTHY"]
    ) == "HEALTHY"

    assert get_overall_health(
        ["HEALTHY", "WARNING", "HEALTHY"]
    ) == "WARNING"

    assert get_overall_health(
        ["WARNING", "WARNING", "HEALTHY"]
    ) == "WARNING"

    assert get_overall_health(
        ["WARNING", "CRITICAL", "HEALTHY"]
    ) == "CRITICAL"

    assert get_overall_health(
        ["CRITICAL", "CRITICAL", "WARNING"]
    ) == "CRITICAL"
