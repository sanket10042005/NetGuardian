def check_health(value):
    if value < 70:
        return "HEALTHY"
    elif value <= 90:
        return "WARNING"
    else:
        return "CRITICAL"


def get_overall_health(statuses):
    if "CRITICAL" in statuses:
        return "CRITICAL"
    elif "WARNING" in statuses:
        return "WARNING"
    else:
        return "HEALTHY"
