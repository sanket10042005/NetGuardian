import psutil


def get_network_interfaces():
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    interfaces = []

    for interface_name in addresses:
        interface_info = {
            "name": interface_name,
            "is_up": stats[interface_name].isup,
            "ip_address": None,
            "netmask": None,
            "mac_address": None,
            "mtu": stats[interface_name].mtu
        }

        for address in addresses[interface_name]:

            if address.family == psutil.AF_LINK:
                interface_info["mac_address"] = address.address

            elif address.family == 2:
                interface_info["ip_address"] = address.address
                interface_info["netmask"] = address.netmask

        interfaces.append(interface_info)

    return interfaces
