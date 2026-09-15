import os
import shutil
import subprocess


def command_exists(command):
    return shutil.which(command) is not None


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return None

        return result.stdout.strip()

    except (
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
        OSError
    ):
        return None


def get_ufw_status():
    if not command_exists("ufw"):
        return {
            "available": False,
            "status": "NOT_INSTALLED"
        }

    if os.geteuid() != 0:
        return {
            "available": True,
            "status": "ACCESS_DENIED"
        }

    output = run_command(["ufw", "status"])

    if output is None:
        return {
            "available": True,
            "status": "ERROR"
        }

    if "Status: active" in output:
        return {
            "available": True,
            "status": "ACTIVE"
        }

    if "Status: inactive" in output:
        return {
            "available": True,
            "status": "INACTIVE"
        }

    return {
        "available": True,
        "status": "UNKNOWN"
    }


def get_nftables_status():
    if not command_exists("nft"):
        return {
            "available": False,
            "status": "NOT_INSTALLED"
        }

    if os.geteuid() != 0:
        return {
            "available": True,
            "status": "ACCESS_DENIED"
        }

    output = run_command(
        ["nft", "list", "ruleset"]
    )

    if output is None:
        return {
            "available": True,
            "status": "ERROR"
        }

    if output:
        return {
            "available": True,
            "status": "RULES_PRESENT"
        }

    return {
        "available": True,
        "status": "NO_RULES"
    }


def get_iptables_status():
    if not command_exists("iptables"):
        return {
            "available": False,
            "status": "NOT_INSTALLED"
        }

    if os.geteuid() != 0:
        return {
            "available": True,
            "status": "ACCESS_DENIED"
        }

    output = run_command(
        ["iptables", "-L", "-n"]
    )

    if output is None:
        return {
            "available": True,
            "status": "ERROR"
        }

    lines = output.splitlines()

    rule_lines = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith("Chain"):
            continue

        if line.startswith("target"):
            continue

        rule_lines.append(line)

    if rule_lines:
        return {
            "available": True,
            "status": "RULES_PRESENT"
        }

    return {
        "available": True,
        "status": "NO_RULES"
    }


def discover_firewalls():
    return {
        "ufw": get_ufw_status(),
        "nftables": get_nftables_status(),
        "iptables": get_iptables_status()
    }
