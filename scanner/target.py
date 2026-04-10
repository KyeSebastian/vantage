import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional


@dataclass
class Target:
    raw: str
    is_ip: bool
    hostname: Optional[str]
    ip: str

    @classmethod
    def from_string(cls, value: str) -> "Target":
        # Strip common URL prefixes so callers can pass bare URLs
        value = value.strip()
        for prefix in ("https://", "http://"):
            if value.lower().startswith(prefix):
                value = value[len(prefix):]
        value = value.rstrip("/").split("/")[0]  # drop any path
        # Strip port if present (e.g., "example.com:8080" → "example.com")
        if not value.startswith("[") and ":" in value:
            value = value.rsplit(":", 1)[0]

        if not value:
            raise ValueError("Target must not be empty.")

        try:
            addr = ipaddress.ip_address(value)
            return cls(raw=value, is_ip=True, hostname=None, ip=str(addr))
        except ValueError:
            pass

        try:
            ip = socket.gethostbyname(value)
            return cls(raw=value, is_ip=False, hostname=value, ip=ip)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {value!r}")
