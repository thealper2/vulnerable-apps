import socket
from ipaddress import IPv4Address, ip_address
from typing import Optional, Tuple

from config import ALLOWED_DOMAINS, BLOCKLIST, AllowedSchemes
from models.security_types import URL, IPAddress, SanitizedURL


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in private range"""
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False


def resolve_domain(domain: str) -> Tuple[Optional[IPAddress], bool]:
    """
    Resolve domain to IP address with DNS rebind protection check
    Returns tuple of (resolved_ip, is_rebinded)
    """
    try:
        # Get all IPs for the domain
        ips = {ip[4][0] for ip in socket.getaddrinfo(domain, None)}

        if len(ips) > 1:
            return None, True  # Potential DNS rebinding

        ip = ips.pop()
        return IPAddress(ip), False
    except socket.gaierror:
        return None, False


def validate_domain(domain: str) -> bool:
    """Check if domain is in allowed list"""
    return domain in ALLOWED_DOMAINS


def sanitize_headers(headers: dict) -> dict:
    """Remove sensitive headers from request"""
    sensitive_headers = {"Cookie", "Authorization", "X-Secret"}
    return {k: v for k, v in headers.items() if k not in sensitive_headers}
