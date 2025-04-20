# utils/network_utils.py
import socket
from ipaddress import IPv4Address, ip_address
from typing import Optional


def get_ip_address(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def is_local_address(ip: str) -> bool:
    """Check if IP is local or loopback"""
    try:
        return ip_address(ip).is_loopback
    except ValueError:
        return False
