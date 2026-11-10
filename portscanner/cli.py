"""
CLI Interface module for PortScanner.
Handles argument parsing, port range expansion, banner printing, and execution configuration.
"""

import argparse
import sys
from typing import List, Optional

from portscanner.aggregator import Colors
from portscanner.services import TOP_100_PORTS

BANNER = r"""
  ____            _   ____                                  
 |  _ \ ___  _ __| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |_) / _ \| '__| __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  __/ (_) | |  | |_ ___) | (_| (_| | | | | | | |  __/ |   
 |_|   \___/|_|   \__|____/ \___\__,_|_| |_|_| |_|\___|_|   
          [ Fast Multi-Threaded TCP Port Scanner ]
"""


def parse_ports(port_arg: Optional[str], top_ports: Optional[int] = None) -> List[int]:
    """
    Parse and validate port specifications:
    - Comma-separated list: "21,22,80,443"
    - Ranges: "1-1024", "8000-8080"
    - Mixed: "22,80-90,443,8000-8080"
    - Full range keyword: "all" or "-" (1-65535)
    - If top_ports is specified, returns the top N common ports.
    - Default: Top 100 common ports.
    """
    if top_ports is not None:
        if top_ports <= 0:
            raise ValueError("--top-ports must be a positive integer.")
        return TOP_100_PORTS[:top_ports]

    if not port_arg:
        # Default to top 100 ports
        return list(TOP_100_PORTS)

    port_arg = port_arg.strip()
    if port_arg.lower() in ("all", "-"):
        return list(range(1, 65536))

    ports_set = set()
    parts = port_arg.split(",")

    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise ValueError(f"Invalid port range format: '{part}'")
            start = int(bounds[0].strip())
            end = int(bounds[1].strip())
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Port range must be between 1 and 65535: '{part}'")
            ports_set.update(range(start, end + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Port must be between 1 and 65535: {p}")
            ports_set.add(p)

    sorted_ports = sorted(list(ports_set))
    if not sorted_ports:
        raise ValueError("No valid ports specified.")
    return sorted_ports


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="PortScanner",
        description="High-performance multi-threaded TCP port scanner with banner grabbing and service detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py 127.0.0.1
  python scanner.py scanme.nmap.org -p 20-100,443,8080
  python scanner.py example.com --top-ports 50 -t 100
  python scanner.py 192.168.1.1 -p all -t 200 --timeout 0.5
  python scanner.py 10.0.0.5 -p 80,443,3306,8080 -oJ scan.json -oN scan.txt
        """
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target IP address or domain name (e.g. 192.168.1.1 or scanme.nmap.org)"
    )

    parser.add_argument(
        "-p", "--ports",
        type=str,
        default=None,
        help="Port(s) to scan: e.g. '80', '21,22,80', '1-1024', or 'all' for 1-65535"
    )

    parser.add_argument(
        "--top-ports",
        type=int,
        default=None,
        help="Scan top N common ports (e.g. --top-ports 50 or --top-ports 100)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=100,
        help="Number of concurrent worker threads (default: 100)"
    )

    parser.add_argument(
        "-w", "--timeout",
        type=float,
        default=1.0,
        help="Timeout per probe in seconds (default: 1.0)"
    )

    parser.add_argument(
        "-b", "--banner",
        action="store_true",
        default=True,
        help="Enable service banner grabbing and fingerprinting (default: enabled)"
    )

    parser.add_argument(
        "--no-banner",
        action="store_false",
        dest="banner",
        help="Disable banner grabbing for faster raw connect scans"
    )

    parser.add_argument(
        "-oJ", "--json",
        type=str,
        default=None,
        metavar="FILE",
        help="Output scan results to a JSON file"
    )

    parser.add_argument(
        "-oN", "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="Output scan results to a plain text file"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (shows closed and filtered ports)"
    )

    parser.add_argument(
        "--ui", "--gui",
        action="store_true",
        dest="gui",
        help="Launch native Desktop Graphical User Interface (GUI)"
    )

    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch interactive Web Dashboard UI in your browser"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable terminal color codes"
    )

    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable interactive progress bar"
    )

    return parser

