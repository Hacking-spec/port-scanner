"""
Target Resolver module for PortScanner.
Handles target validation, domain name resolution, and reverse DNS lookups.
"""

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ResolvedTarget:
    """Represents a resolved scan target."""
    raw_target: str
    ip: str = ""
    hostname: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    all_ips: List[str] = field(default_factory=list)
    is_valid: bool = False
    error_message: Optional[str] = None

    def __str__(self) -> str:
        if not self.is_valid:
            return f"Invalid Target '{self.raw_target}': {self.error_message}"
        if self.hostname and self.hostname != self.ip:
            return f"{self.raw_target} [{self.ip}] ({self.hostname})"
        return f"{self.raw_target} [{self.ip}]"


class TargetResolver:
    """
    Validates IP addresses and resolves domain names to IP addresses.
    """

    @classmethod
    def resolve_targets(cls, targets_input: str) -> List[ResolvedTarget]:
        """
        Resolve a list of comma-separated targets or a file path containing targets.
        """
        import os
        results: List[ResolvedTarget] = []

        if os.path.isfile(targets_input):
            with open(targets_input, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                for line in lines:
                    results.append(cls.resolve(line))
            return results

        parts = [p.strip() for p in targets_input.split(",") if p.strip()]
        for p in parts:
            results.append(cls.resolve(p))
        return results

    @staticmethod
    def is_valid_ip(address_str: str) -> bool:
        """Check whether the string is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(address_str)
            return True
        except ValueError:
            return False

    @classmethod
    def resolve(cls, target: str) -> ResolvedTarget:
        """
        Resolve domain or validate IP address.

        Args:
            target: Domain name (e.g. 'scanme.nmap.org') or IP (e.g. '192.168.1.1')

        Returns:
            ResolvedTarget instance containing IP, hostname, and status.
        """
        target = target.strip()
        if not target:
            return ResolvedTarget(
                raw_target=target,
                is_valid=False,
                error_message="Target string cannot be empty."
            )

        # Remove protocol prefixes if user accidentally passed http:// or https://
        if target.startswith("http://"):
            target = target[7:]
        elif target.startswith("https://"):
            target = target[8:]

        # Case 1: CIDR network (e.g. 192.168.1.0/28)
        if "/" in target and target.split("/")[-1].isdigit():
            try:
                network = ipaddress.ip_network(target, strict=False)
                # If network has only 1 address (/32)
                if network.num_addresses == 1:
                    ip_str = str(network.network_address)
                    return cls.resolve(ip_str)
                # Network with multiple hosts
                hosts = [str(ip) for ip in network.hosts()]
                if not hosts:
                    hosts = [str(network.network_address)]
                return ResolvedTarget(
                    raw_target=target,
                    ip=hosts[0],
                    all_ips=hosts,
                    is_valid=True
                )
            except ValueError:
                pass

        # Strip any trailing URL path or port (e.g. host:8080/path)
        if "/" in target:
            target = target.split("/")[0]
        if ":" in target and target.count(":") == 1:
            target = target.split(":")[0]

        # Case 2: Direct IP address provided
        if cls.is_valid_ip(target):
            ip_obj = ipaddress.ip_address(target)
            ip_str = str(ip_obj)
            hostname = None
            try:
                # Attempt reverse DNS lookup
                rev_host, _, _ = socket.gethostbyaddr(ip_str)
                hostname = rev_host
            except (socket.herror, socket.gaierror, OSError):
                hostname = None

            return ResolvedTarget(
                raw_target=target,
                ip=ip_str,
                hostname=hostname,
                all_ips=[ip_str],
                is_valid=True
            )

        # Case 3: Hostname / Domain provided -> resolve via DNS
        try:
            # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            canonical_name, aliases, ip_list = socket.gethostbyname_ex(target)
            if not ip_list:
                return ResolvedTarget(
                    raw_target=target,
                    is_valid=False,
                    error_message=f"DNS resolution for '{target}' returned no IP addresses."
                )

            primary_ip = ip_list[0]
            return ResolvedTarget(
                raw_target=target,
                ip=primary_ip,
                hostname=canonical_name or target,
                aliases=aliases,
                all_ips=ip_list,
                is_valid=True
            )
        except socket.gaierror as e:
            return ResolvedTarget(
                raw_target=target,
                is_valid=False,
                error_message=f"Could not resolve host '{target}': {e.strerror or str(e)}"
            )
        except Exception as e:
            return ResolvedTarget(
                raw_target=target,
                is_valid=False,
                error_message=f"Resolution error for '{target}': {str(e)}"
            )

