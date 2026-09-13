import socket

import psutil


def discover_network_interfaces():
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    interfaces = []

    for interface_name, interface_addresses in addresses.items():

        interface = {
            "name": interface_name,
            "is_up": False,
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "mac_address": None,

            "mtu": None
        }

        if interface_name in stats:
            interface["is_up"] = stats[interface_name].isup
            interface["mtu"] = stats[interface_name].mtu

        for address in interface_addresses:

            if address.family == psutil.AF_LINK:
                interface["mac_address"] = address.address

            elif address.family == socket.AF_INET:
                interface["ipv4_addresses"].append({
                    "address": address.address,
                    "netmask": address.netmask
                })

            elif address.family == socket.AF_INET6:
                interface["ipv6_addresses"].append({
                    "address": address.address,
                    "netmask": address.netmask
                })

        interfaces.append(interface)

    return interfaces
