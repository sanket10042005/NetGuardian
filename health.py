
WARNING_THRESHOLD = 70
CRITICAL_THRESHOLD = 90


def check_health(value):
    if value < WARNING_THRESHOLD:
        return "HEALTHY"
    elif value <= CRITICAL_THRESHOLD:
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
