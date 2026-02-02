"""
Isnad Security Module

SSRF protection, rate limiting, and input validation.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Optional, Tuple
import time
from collections import defaultdict


class SSRFProtection:
    """Protect against Server-Side Request Forgery attacks."""
    
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
        ipaddress.ip_network('fe80::/10'),
    ]
    
    BLOCKED_HOSTS = [
        'localhost', 'metadata.google.internal', 
        'metadata.internal', '169.254.169.254', 'metadata',
    ]
    
    ALLOWED_SCHEMES = ['https']
    
    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, Optional[str]]:
        """Validate a URL is safe to fetch."""
        try:
            parsed = urlparse(url)
            
            if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
                return False, f"Scheme '{parsed.scheme}' not allowed. Use HTTPS."
            
            if not parsed.hostname:
                return False, "URL must have a hostname"
            
            hostname = parsed.hostname.lower()
            
            for blocked in cls.BLOCKED_HOSTS:
                if blocked in hostname:
                    return False, f"Hostname '{hostname}' is blocked"
            
            try:
                ips = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
                
                for family, type_, proto, canonname, sockaddr in ips:
                    ip = ipaddress.ip_address(sockaddr[0])
                    
                    for private_range in cls.PRIVATE_RANGES:
                        if ip in private_range:
                            return False, f"IP resolves to private range"
                    
            except socket.gaierror as e:
                return False, f"DNS resolution failed: {e}"
            
            return True, None
            
        except Exception as e:
            return False, f"URL validation error: {e}"


class RateLimiter:
    """In-memory rate limiter using sliding window."""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.limits = {
            'scan': {'window': 3600, 'max': 20},
            'registry': {'window': 60, 'max': 60},
            'default': {'window': 60, 'max': 100},
        }
    
    def is_allowed(self, identifier: str, action: str = 'default') -> Tuple[bool, dict]:
        config = self.limits.get(action, self.limits['default'])
        window, max_req = config['window'], config['max']
        
        key = f"{identifier}:{action}"
        now = time.time()
        cutoff = now - window
        
        self.requests[key] = [ts for ts in self.requests[key] if ts > cutoff]
        
        current = len(self.requests[key])
        remaining = max(0, max_req - current)
        
        info = {'remaining': remaining, 'limit': max_req}
        
        if current >= max_req:
            return False, info
        
        self.requests[key].append(now)
        return True, {**info, 'remaining': remaining - 1}


rate_limiter = RateLimiter()
ssrf_protection = SSRFProtection()
