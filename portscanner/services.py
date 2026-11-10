"""
Service definitions, port catalogs, and protocol signatures for PortScanner.
"""

import socket
from typing import Dict, List, Optional

# Top 100 most common TCP ports (based on Nmap statistics)
TOP_100_PORTS: List[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646,
    7070, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 10000,
    27017, 32768, 49152, 49153, 49154
]

# Extended common services database with friendly descriptions
COMMON_SERVICES: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Mail)",
    26: "SMTP-Alt",
    43: "WHOIS",
    53: "DNS (Domain Name System)",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    79: "Finger",
    80: "HTTP (Web Server)",
    81: "HTTP-Alt / Tor",
    88: "Kerberos",
    110: "POP3 (Post Office Protocol)",
    111: "RPCBind / Portmap",
    113: "Ident",
    119: "NNTP (Usenet)",
    123: "NTP (Network Time)",
    135: "MSRPC (Windows RPC)",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP (Internet Message Access)",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP (Border Gateway)",
    194: "IRC",
    389: "LDAP",
    427: "SLP (Service Location)",
    443: "HTTPS (HTTP over TLS/SSL)",
    445: "Microsoft-DS (SMB/Active Directory)",
    465: "SMTPS (SMTP over SSL)",
    514: "Syslog",
    515: "LPD (Printer Daemon)",
    548: "AFP (Apple Filing Protocol)",
    554: "RTSP (Real-Time Streaming)",
    587: "SMTP (Submission)",
    631: "IPP (Internet Printing)",
    636: "LDAPS (LDAP over SSL)",
    873: "Rsync",
    990: "FTPS (FTP over SSL)",
    993: "IMAPS (IMAP over SSL)",
    995: "POP3S (POP3 over SSL)",
    1080: "SOCKS Proxy",
    1433: "MSSQL (Microsoft SQL Server)",
    1434: "MSSQL Monitor",
    1521: "Oracle Database",
    1723: "PPTP (VPN)",
    1883: "MQTT",
    2049: "NFS (Network File System)",
    2181: "Apache ZooKeeper",
    2375: "Docker REST API (Unencrypted)",
    2376: "Docker REST API (TLS)",
    3000: "Node.js / React / Dev Web",
    3128: "Squid HTTP Proxy",
    3306: "MySQL Database",
    3389: "MS-WBT-Server (RDP Remote Desktop)",
    4369: "Erlang Port Mapper (EPMD)",
    5000: "Flask / Dev Web / Synology",
    5432: "PostgreSQL Database",
    5672: "RabbitMQ (AMQP)",
    5900: "VNC Remote Desktop",
    5901: "VNC-1",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis Key-Value Store",
    6443: "Kubernetes API Server",
    7000: "Cassandra Internode",
    8000: "HTTP Dev Server (Django/Python)",
    8008: "HTTP-Alt",
    8080: "HTTP Proxy / Tomcat / Spring",
    8081: "HTTP-Alt (Blackice / Node)",
    8443: "HTTPS-Alt / Tomcat SSL",
    8888: "HTTP-Alt / Jupyter Notebook",
    9000: "SonarQube / PHP-FPM / MinIO",
    9090: "Prometheus / Cockpit",
    9092: "Apache Kafka",
    9100: "Jetdirect Printer / Node Exporter",
    9200: "Elasticsearch HTTP",
    9300: "Elasticsearch Cluster",
    10000: "Webmin / Network Management",
    11211: "Memcached",
    27017: "MongoDB Database",
    50000: "SAP / IBM DB2",
}

# Security risk advisories and best practice recommendations for commonly exposed ports
SECURITY_ADVISORIES: Dict[int, str] = {
    21: "Cleartext FTP: Credentials sent in plaintext. Recommend upgrading to SFTP (port 22) or FTPS (port 990).",
    23: "Insecure Telnet: Unencrypted remote terminal. High risk of eavesdropping. Migrate to SSH immediately.",
    80: "Unencrypted HTTP: Web traffic not encrypted with TLS. Enforce HTTPS redirect and HSTS.",
    135: "Windows RPC: High-value lateral movement target (MS-RPC). Should not be exposed to public networks.",
    139: "NetBIOS Session: Legacy NetBIOS protocol. Disable if not required; keep behind firewall.",
    445: "SMB / Active Directory: High-risk target for ransomware (e.g. WannaCry/EternalBlue). Block on WAN.",
    1433: "MSSQL Database: Database server exposed. Ensure strong SA password and disable xp_cmdshell.",
    2375: "Unencrypted Docker Daemon: Remote root code execution vector. Restrict access or enable TLS (port 2376).",
    3306: "MySQL Database: Database port exposed. Restrict bind-address to 127.0.0.1 or trusted subnets.",
    3389: "RDP (Remote Desktop): Frequently targeted by brute-force bots and BlueKeep. Require NLA and MFA/VPN.",
    5432: "PostgreSQL Database: Database exposed. Verify pg_hba.conf restrictions and SSL enforcement.",
    5900: "VNC Remote Desktop: Often configured with weak or no passwords. Require encryption / tunnel over SSH.",
    6379: "Redis Key-Value Store: Known for unauthenticated RCE exploits. Ensure 'requirepass' and bind to localhost.",
    9200: "Elasticsearch HTTP: Open Elasticsearch clusters frequently leaked. Enable Security (Elastic Shield/X-Pack).",
    11211: "Memcached: Exploited for UDP/TCP reflection DDoS attacks. Bind to loopback interface only.",
    27017: "MongoDB Database: Historical target for ransomware wiper attacks. Enforce authentication and firewalling.",
}

def get_security_advisory(port: int) -> Optional[str]:
    """Retrieve security recommendation or advisory for exposed port if known."""
    return SECURITY_ADVISORIES.get(port)

def get_service_name(port: int, proto: str = "tcp") -> str:
    """
    Resolve port to a well-known service name.
    Checks the built-in dictionary first, then falls back to socket.getservbyport.
    """
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, proto).upper()
    except (OSError, socket.error):
        return "Unknown"

