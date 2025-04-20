import socket
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, Timeout

from ..config import BLOCKLIST, REQUEST_TIMEOUT, AllowedSchemes
from ..models.security_types import URL, SanitizedURL
from .validators import is_private_ip, resolve_domain, sanitize_headers, validate_domain


class SSRFProtection:
    """Implements various SSRF protection mechanisms"""

    @staticmethod
    def make_request_vulnerable(
        url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """
        Vulnerable SSRF implementation with no protections
        WARNING: This is intentionally vulnerable - never use in production!
        """
        try:
            response = requests.request(method, url, headers=headers)
            return response.text
        except RequestException as e:
            return str(e)

    @staticmethod
    def blocklist_protection(
        url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """SSRF protection using blocklist approach"""
        parsed = urlparse(url)

        # Check against blocklist domains
        if parsed.netloc in BLOCKLIST:
            return "Blocked: Domain in blocklist"

        # Check for private IPs
        try:
            ip = socket.gethostbyname(parsed.netloc)
            if is_private_ip(ip):
                return "Blocked: Private IP range"
        except socket.gaierror:
            pass

        return SSRFProtection.make_request_vulnerable(url, method, headers)

    @staticmethod
    def allowlist_protection(
        url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """SSRF protection using allowlist approach"""
        parsed = urlparse(url)
        if not validate_domain(parsed.netloc):
            return "Blocked: Domain not in allowlist"

        return SSRFProtection.make_request_vulnerable(url, method, headers)

    @staticmethod
    def domain_validation(
        url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """SSRF protection with domain validation and DNS checks"""
        parsed = urlparse(url)
        domain = parsed.netloc

        # DNS resolution with rebinding protection
        ip, is_rebinded = resolve_domain(domain)
        if is_rebinded:
            return "Blocked: DNS rebinding detected"

        if ip and is_private_ip(ip):
            return "Blocked: Private IP address"

        return SSRFProtection.make_request_vulnerable(url, method, headers)

    @staticmethod
    def ip_block_protection(
        url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """SSRF protection with IP blocking"""
        parsed = urlparse(url)

        try:
            ip = socket.gethostbyname(parsed.netloc)
            if ip in BLOCKLIST:
                return "Blocked: IP in blocklist"
        except socket.gaierror:
            pass

        return SSRFProtection.make_request_vulnerable(url, method, headers)

    @staticmethod
    def timeout_protection(
        url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """SSRF protection with request timeout"""
        try:
            response = requests.request(
                method, url, headers=headers, timeout=REQUEST_TIMEOUT
            )
            return response.text
        except Timeout:
            return "Blocked: Request timeout"
        except RequestException as e:
            return str(e)

    @staticmethod
    def scheme_filter_protection(
        url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """SSRF protection with URL scheme filtering"""
        parsed = urlparse(url)
        if parsed.scheme not in [s.value for s in AllowedSchemes]:
            return f"Blocked: Scheme {parsed.scheme} not allowed"

        return SSRFProtection.make_request_vulnerable(url, method, headers)

    @staticmethod
    def header_sanitization(
        url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """SSRF protection with header sanitization"""
        safe_headers = sanitize_headers(headers) if headers else None
        return SSRFProtection.make_request_vulnerable(url, method, safe_headers)

    @staticmethod
    def method_restriction(
        url: str, method: str = "GET", headers: Optional[Dict] = None
    ) -> str:
        """SSRF protection with HTTP method restriction"""
        if method.upper() != "GET":
            return "Blocked: Only GET method allowed"

        return SSRFProtection.make_request_vulnerable(url, method, headers)
