import ipaddress
from typing import List


def parse_cidr(cidr: str) -> List[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]


def parse_target(target: str) -> List[str]:
    if "/" in target:
        return parse_cidr(target)
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        raise ValueError(f"Invalid target: {target}")
