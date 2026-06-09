"""
utils.py — Target resolution, address-family detection, validation.
"""

import ipaddress
import re
import socket


def resolve_target(target):
    """
    Resolve target (hostname or IP string) to its canonical IP address.
    Returns None if resolution fails.

    For IPv6 literals wrapped in brackets (e.g. "[::1]") the brackets
    are stripped before resolution.
    """
    if target.startswith("[") and target.endswith("]"):
        target = target[1:-1]

    try:
        infos = socket.getaddrinfo(target, None)
        return infos[0][4][0]
    except socket.gaierror:
        return None


def detect_address_family(ip):
    """
    Return the socket address-family constant and label for ip.

    Returns (AF_INET, "IPv4") or (AF_INET6, "IPv6")
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            return socket.AF_INET6, "IPv6"
        return socket.AF_INET, "IPv4"
    except ValueError:
        return socket.AF_INET, "IPv4"


def is_valid_target(target):
    """
    Return True if target looks like a resolvable hostname, IPv4, or IPv6.
    Does NOT perform actual DNS resolution — just a syntax check.
    """
    stripped = target.strip("[]")

    try:
        ipaddress.ip_address(stripped)
        return True
    except ValueError:
        pass

    try:
        ipaddress.ip_network(stripped, strict=False)
        return True
    except ValueError:
        pass

    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
    )
    return bool(hostname_re.match(stripped)) and len(stripped) <= 253


def format_duration(seconds):
    """
    Human-readable scan duration: '0.42s', '2m 05s', etc.
    """
    if seconds < 60:
        return "%.2fs" % seconds
    minutes = int(seconds // 60)
    secs = seconds % 60
    return "%dm %05.2fs" % (minutes, secs)