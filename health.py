def check_health(value):
    if value < 70:
        return "HEALTHY"
    elif value <= 90:
        return "WARNING"
    else:
        return "CRITICAL"
