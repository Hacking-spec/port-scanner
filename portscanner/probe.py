"""
Socket Probe module for PortScanner.
Performs TCP connect scanning, measures latency, and performs banner grabbing / service fingerprinting.
"""

import errno
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from portscanner.services import get_service_name


@dataclass
class PortResult:
    """Represents the scan result for a single port."""
    port: int
    state: str  # "OPEN", "CLOSED", "FILTERED", "OPEN|FILTERED"
    protocol: str = "tcp"  # "tcp" or "udp"
    service: str = "Unknown"
    banner: Optional[str] = None
    latency_ms: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        return self.state in ("OPEN", "OPEN|FILTERED")


class SocketProbe:
    """
    Performs TCP connect probes and service banner grabbing against target ports.
    """

    def __init__(self, timeout: float = 1.0, banner_grab: bool = True):
        self.timeout = timeout
        self.banner_grab = banner_grab

    def probe(self, ip: str, port: int) -> PortResult:
        """
        Probe a single TCP port on target IP.

        Returns:
            PortResult with state, service, banner, and latency.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        start_time = time.perf_counter()
        try:
            err = sock.connect_ex((ip, port))
            latency = (time.perf_counter() - start_time) * 1000.0

            if err == 0:
                service = get_service_name(port)
                banner = None
                extra: Dict[str, Any] = {}

                if self.banner_grab:
                    banner, extra = self._grab_banner(sock, ip, port)

                sock.close()
                return PortResult(
                    port=port,
                    state="OPEN",
                    service=service,
                    banner=banner,
                    latency_ms=round(latency, 2),
                    extra=extra
                )

            # Check error codes
            sock.close()
            # Windows WSAECONNREFUSED is 10061, standard ECONNREFUSED is errno.ECONNREFUSED (111)
            # Windows WSAETIMEDOUT is 10060, standard ETIMEDOUT is errno.ETIMEDOUT (110)
            conn_refused_codes = {errno.ECONNREFUSED, 10061}
            timed_out_codes = {errno.ETIMEDOUT, 10060}

            if err in conn_refused_codes:
                state = "CLOSED"
            elif err in timed_out_codes:
                state = "FILTERED"
            else:
                state = "CLOSED"

            return PortResult(
                port=port,
                state=state,
                service=get_service_name(port),
                latency_ms=round(latency, 2)
            )

        except (socket.timeout, TimeoutError):
            latency = (time.perf_counter() - start_time) * 1000.0
            sock.close()
            return PortResult(
                port=port,
                state="FILTERED",
                service=get_service_name(port),
                latency_ms=round(latency, 2)
            )
        except OSError:
            latency = (time.perf_counter() - start_time) * 1000.0
            sock.close()
            return PortResult(
                port=port,
                state="FILTERED",
                service=get_service_name(port),
                latency_ms=round(latency, 2)
            )
        except Exception:
            sock.close()
            return PortResult(
                port=port,
                state="CLOSED",
                service=get_service_name(port)
            )

    def _grab_banner(self, sock: socket.socket, ip: str, port: int) -> tuple[Optional[str], Dict[str, Any]]:
        """
        Grab service banner using passive read, protocol-specific probes, or TLS inspection.
        """
        banner: Optional[str] = None
        extra: Dict[str, Any] = {}

        # Set a short timeout for banner grabbing to avoid slowing down the scan
        grab_timeout = min(self.timeout, 1.2)
        sock.settimeout(grab_timeout)

        # 1. SSL/TLS ports (443, 8443, etc.)
        if port in {443, 8443, 993, 995, 465, 636}:
            return self._grab_tls_banner(ip, port, grab_timeout)

        # 2. Passive listening for banner (e.g. SSH, FTP, SMTP, MySQL)
        try:
            data = sock.recv(1024)
            if data:
                banner = self._clean_banner(data)
                return banner, extra
        except (socket.timeout, TimeoutError):
            pass
        except OSError:
            pass

        # 3. Active probes based on common ports
        # HTTP ports
        if port in {80, 8000, 8080, 8081, 8888, 3000, 5000} or "HTTP" in get_service_name(port):
            try:
                http_probe = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: PortScanner/1.0\r\nConnection: close\r\n\r\n"
                sock.sendall(http_probe.encode("ascii", errors="ignore"))
                response = sock.recv(4096).decode("latin-1", errors="replace")
                
                parts = []
                # Check for Server header
                server_match = re.search(r"Server:\s*([^\r\n]+)", response, re.IGNORECASE)
                if server_match:
                    parts.append(f"Server: {server_match.group(1).strip()}")

                # Check for HTML Title tag
                title_match = re.search(r"<title[^>]*>([^<]+)</title>", response, re.IGNORECASE)
                if title_match:
                    title_text = title_match.group(1).strip()
                    if title_text:
                        parts.append(f"Title: {title_text}")

                if parts:
                    banner = " | ".join(parts)
                else:
                    status_line = response.split("\r\n")[0].strip()
                    if status_line.startswith("HTTP/"):
                        banner = status_line
                return banner, extra
            except Exception:
                pass

        # MySQL greeting probe (port 3306)
        if port == 3306:
            try:
                data = sock.recv(256)
                if data and len(data) > 5:
                    # In MySQL handshake packet: byte 4 is protocol version, followed by null-terminated version string
                    null_idx = data.find(b"\x00", 5)
                    if null_idx != -1:
                        mysql_ver = data[5:null_idx].decode("latin-1", errors="replace")
                        banner = f"MySQL Server {mysql_ver}"
                        return banner, extra
            except Exception:
                pass

        # Redis probe
        if port == 6379:
            try:
                sock.sendall(b"PING\r\n")
                resp = sock.recv(256).decode("utf-8", errors="replace").strip()
                if resp:
                    banner = f"Redis ({resp})"
                    return banner, extra
            except Exception:
                pass

        # Generic probe fallback: Send CRLF to trigger greeting
        try:
            sock.sendall(b"\r\n\r\n")
            data = sock.recv(512)
            if data:
                banner = self._clean_banner(data)
        except Exception:
            pass

        return banner, extra

    def _grab_tls_banner(self, ip: str, port: int, timeout: float) -> tuple[Optional[str], Dict[str, Any]]:
        """Connect with TLS to inspect certificate and negotiate handshake."""
        extra: Dict[str, Any] = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=timeout) as plain_sock:
                with context.wrap_socket(plain_sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    info_parts = []
                    if version:
                        info_parts.append(version)
                    if cipher:
                        info_parts.append(cipher[0])

                    # Try to fetch HTTP title/server over TLS
                    try:
                        ssock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                        resp = ssock.recv(1024).decode("latin-1", errors="replace")
                        server_m = re.search(r"Server:\s*([^\r\n]+)", resp, re.IGNORECASE)
                        if server_m:
                            info_parts.append(f"Server: {server_m.group(1).strip()}")
                    except Exception:
                        pass

                    banner = " | ".join(info_parts) if info_parts else f"TLS Handshake OK ({version})"
                    extra["cipher"] = cipher
                    extra["version"] = version
                    return banner, extra
        except Exception:
            return None, extra

    @staticmethod
    def _clean_banner(raw_bytes: bytes) -> str:
        """Sanitize raw banner bytes into a readable single-line string."""
        text = raw_bytes.decode("utf-8", errors="replace")
        # Replace newlines and tabs with spaces
        text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        # Filter unprintable characters
        text = "".join(ch for ch in text if ch.isprintable() or ch == " ")
        # Collapse multiple spaces
        text = re.sub(r"\s+", " ", text).strip()
        # Truncate if too long
        if len(text) > 80:
            text = text[:77] + "..."
        return text

