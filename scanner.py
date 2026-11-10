#!/usr/bin/env python3
"""
PortScanner - High-Performance Modular TCP Port Scanner
Architecture:
  [ CLI Interface ] -> [ Target Resolver ] -> [ ThreadPool Engine ]
                                                    |
                                      [ Worker 1 ... Worker N ]
                                                    |
                                            [ Socket Probe ]
                                                    |
                                          [ Result Aggregator ]
"""

import sys
from datetime import datetime

from portscanner.aggregator import Colors, ResultAggregator
from portscanner.cli import BANNER, build_parser, parse_ports
from portscanner.engine import ThreadPoolEngine
from portscanner.probe import SocketProbe
from portscanner.target_resolver import TargetResolver


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Launch Desktop GUI if requested
    if getattr(args, "gui", False):
        try:
            from portscanner.gui import launch_gui
            launch_gui()
            return 0
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to launch Desktop GUI: {e}{Colors.RESET}")
            return 1

    # Launch Web UI Dashboard if requested
    if getattr(args, "web", False):
        try:
            from portscanner.web_ui import launch_web_ui
            launch_web_ui()
            return 0
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to launch Web UI: {e}{Colors.RESET}")
            return 1

    # If no target provided, print help banner and exit
    if not args.target:
        print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
        parser.print_help()
        print(f"\n{Colors.RED}Error: Target host or IP address is required (or use --ui / --web to launch graphical interface).{Colors.RESET}\n")
        return 1

    if args.no_color:
        Colors.disable()

    # Step 1: CLI & Banner Presentation
    print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")

    # Parse ports
    try:
        ports = parse_ports(args.ports, args.top_ports)
    except ValueError as e:
        print(f"{Colors.RED}[!] Port specification error: {e}{Colors.RESET}")
        return 1

    # Step 2: Target Resolver
    print(f"{Colors.BOLD}[*] Resolving target: {args.target}...{Colors.RESET}")
    resolved = TargetResolver.resolve(args.target)
    if not resolved.is_valid:
        print(f"{Colors.RED}[!] Target resolution failed: {resolved.error_message}{Colors.RESET}")
        return 1

    host_info = f"{resolved.hostname} ({resolved.ip})" if resolved.hostname else resolved.ip
    print(f"{Colors.GREEN}[+] Target resolved successfully:{Colors.RESET} {host_info}")
    if len(resolved.all_ips) > 1:
        print(f"    Additional IP(s): {', '.join(resolved.all_ips[1:])}")

    print(
        f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Ports: {len(ports)} | Threads: {args.threads} | Timeout: {args.timeout}s | "
        f"Service Detection: {'ON' if args.banner else 'OFF'}\n"
    )

    # Step 3: Result Aggregator Initialization
    aggregator = ResultAggregator(
        target=resolved,
        total_ports=len(ports),
        verbose=args.verbose,
        no_color=args.no_color
    )

    # Step 4: Socket Probe Configuration
    probe = SocketProbe(
        timeout=args.timeout,
        banner_grab=args.banner
    )

    # Step 5: ThreadPool Engine Execution
    engine = ThreadPoolEngine(
        target_ip=resolved.ip,
        ports=ports,
        probe=probe,
        aggregator=aggregator,
        num_threads=args.threads,
        show_progress=not args.no_progress
    )

    try:
        engine.run()
    except KeyboardInterrupt:
        pass

    # Step 6: Render Summary Report & Export
    aggregator.print_summary_table()

    if args.json:
        aggregator.export_json(args.json)

    if args.output:
        aggregator.export_txt(args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())

