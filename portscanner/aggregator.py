"""
Result Aggregator module for PortScanner.
Aggregates scan results thread-safely, tracks metrics, and generates terminal reports / JSON / text exports.
"""

import json
import os
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from portscanner.probe import PortResult
from portscanner.services import get_security_advisory
from portscanner.target_resolver import ResolvedTarget


# ANSI Terminal Colors
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def disable(cls):
        """Disable all colors for non-terminal outputs."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.GREEN = ""
        cls.RED = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""
        cls.WHITE = ""


# Auto-enable ANSI color support on Windows
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004)
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


class ResultAggregator:
    """
    Thread-safe storage and report generator for port scan results.
    """

    def __init__(self, target: ResolvedTarget, total_ports: int, verbose: bool = False, no_color: bool = False):
        self.target = target
        self.total_ports = total_ports
        self.verbose = verbose
        if no_color or not sys.stdout.isatty():
            Colors.disable()

        self._lock = threading.Lock()
        self.open_ports: List[PortResult] = []
        self.closed_ports: List[PortResult] = []
        self.filtered_ports: List[PortResult] = []
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    def start(self) -> None:
        """Mark scan start timestamp."""
        self.start_time = time.time()

    def finish(self) -> None:
        """Mark scan finish timestamp."""
        self.end_time = time.time()

    @property
    def elapsed_time(self) -> float:
        if self.end_time > 0:
            return round(self.end_time - self.start_time, 2)
        if self.start_time > 0:
            return round(time.time() - self.start_time, 2)
        return 0.0

    def add_result(self, result: PortResult, live_notify: bool = True) -> None:
        """Add a port scan result thread-safely."""
        with self._lock:
            if result.state == "OPEN":
                self.open_ports.append(result)
                if live_notify:
                    self._print_live_open(result)
            elif result.state == "FILTERED":
                self.filtered_ports.append(result)
                if self.verbose:
                    print(f"  {Colors.YELLOW}[?] Port {result.port}/tcp filtered ({result.service}){Colors.RESET}")
            else:
                self.closed_ports.append(result)
                if self.verbose:
                    print(f"  {Colors.DIM}[-] Port {result.port}/tcp closed ({result.service}){Colors.RESET}")

    def _print_live_open(self, result: PortResult) -> None:
        """Print an open port discovery immediately."""
        banner_snippet = f" -> {Colors.DIM}{result.banner}{Colors.RESET}" if result.banner else ""
        latency_str = f"({result.latency_ms}ms)"
        print(
            f"  {Colors.GREEN}[+]{Colors.RESET} Discovered open port {Colors.BOLD}{Colors.CYAN}{result.port}/tcp{Colors.RESET} "
            f"on {self.target.ip} [{Colors.YELLOW}{result.service}{Colors.RESET}] {Colors.DIM}{latency_str}{Colors.RESET}{banner_snippet}"
        )

    def print_summary_table(self) -> None:
        """Print a formatted table containing all open ports and summary metrics."""
        # Sort open ports numerically
        sorted_open = sorted(self.open_ports, key=lambda r: r.port)

        print("\n" + "=" * 80)
        print(f"{Colors.BOLD}{Colors.CYAN}PORT SCAN RESULTS:{Colors.RESET} {self.target.raw_target} ({self.target.ip})")
        print("=" * 80)

        if not sorted_open:
            print(f"\n{Colors.YELLOW}No open ports found among {self.total_ports} scanned ports.{Colors.RESET}")
            if self.filtered_ports:
                print(f"{Colors.DIM}(Filtered/unresponsive ports: {len(self.filtered_ports)}){Colors.RESET}")
        else:
            # Header
            header = f"{'PORT':<10} {'STATE':<8} {'SERVICE':<28} {'LATENCY':<10} {'BANNER / VERSION':<30}"
            print(f"{Colors.BOLD}{header}{Colors.RESET}")
            print("-" * 80)

            for res in sorted_open:
                port_str = f"{res.port}/tcp"
                state_str = f"{Colors.GREEN}open{Colors.RESET}"
                service_str = res.service[:26]
                latency_str = f"{res.latency_ms:.1f}ms"
                banner_str = (res.banner or "—")[:30]

                print(f"{port_str:<10} {state_str:<17} {service_str:<28} {latency_str:<10} {Colors.DIM}{banner_str}{Colors.RESET}")

        print("-" * 80)
        print(
            f"{Colors.BOLD}Summary:{Colors.RESET} {Colors.GREEN}{len(self.open_ports)} open{Colors.RESET}, "
            f"{Colors.DIM}{len(self.closed_ports)} closed{Colors.RESET}, "
            f"{Colors.YELLOW}{len(self.filtered_ports)} filtered{Colors.RESET} | "
            f"Total ports: {self.total_ports} | Time elapsed: {self.elapsed_time}s"
        )
        print("=" * 80 + "\n")

    def to_dict(self) -> Dict[str, Any]:
        """Convert results to a dictionary representation."""
        sorted_open = sorted(self.open_ports, key=lambda r: r.port)
        return {
            "target": {
                "raw": self.target.raw_target,
                "ip": self.target.ip,
                "hostname": self.target.hostname,
                "all_ips": self.target.all_ips
            },
            "scan_metadata": {
                "timestamp": datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
                "elapsed_seconds": self.elapsed_time,
                "total_scanned": self.total_ports,
                "open_count": len(self.open_ports),
                "closed_count": len(self.closed_ports),
                "filtered_count": len(self.filtered_ports)
            },
            "open_ports": [
                {
                    "port": r.port,
                    "protocol": "tcp",
                    "state": r.state.lower(),
                    "service": r.service,
                    "banner": r.banner,
                    "latency_ms": r.latency_ms,
                    "extra": r.extra
                }
                for r in sorted_open
            ]
        }

    def export_json(self, file_path: str) -> None:
        """Export results to a JSON file."""
        data = self.to_dict()
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"{Colors.GREEN}[*]{Colors.RESET} Scan results saved to JSON: {file_path}")

    def export_txt(self, file_path: str) -> None:
        """Export results to a plain text file."""
        sorted_open = sorted(self.open_ports, key=lambda r: r.port)
        lines = [
            f"# PortScanner Scan Report",
            f"# Target: {self.target.raw_target} ({self.target.ip})",
            f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Scanned {self.total_ports} ports in {self.elapsed_time} seconds",
            "",
            f"{'PORT':<10} {'STATE':<8} {'SERVICE':<28} {'LATENCY':<10} {'BANNER'}",
            "-" * 80
        ]
        for res in sorted_open:
            banner = res.banner or "—"
            lines.append(f"{res.port}/tcp".ljust(10) + f"{res.state.lower()}".ljust(8) + f"{res.service}".ljust(28) + f"{res.latency_ms}ms".ljust(10) + banner)

        lines.extend([
            "-" * 80,
            f"Open: {len(self.open_ports)} | Closed: {len(self.closed_ports)} | Filtered: {len(self.filtered_ports)}"
        ])

        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"{Colors.GREEN}[*]{Colors.RESET} Scan results saved to Text: {file_path}")

    def export_csv(self, file_path: str) -> None:
        """Export results to a CSV file."""
        import csv
        sorted_open = sorted(self.open_ports, key=lambda r: r.port)
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Port", "Protocol", "State", "Service", "Latency (ms)", "Banner", "Security Advisory"])
            for r in sorted_open:
                adv = get_security_advisory(r.port) or ""
                writer.writerow([r.port, "tcp", r.state, r.service, r.latency_ms, r.banner or "", adv])
        print(f"{Colors.GREEN}[*]{Colors.RESET} Scan results saved to CSV: {file_path}")

    def export_html(self, file_path: str) -> None:
        """Export results to an interactive, modern standalone HTML report."""
        import html
        sorted_open = sorted(self.open_ports, key=lambda r: r.port)
        rows_html = []
        for r in sorted_open:
            adv = get_security_advisory(r.port)
            adv_html = f'<div class="advisory">⚠️ {html.escape(adv)}</div>' if adv else '<span class="dim">—</span>'
            rows_html.append(f"""
            <tr>
              <td><span class="port-badge">{r.port}/tcp</span></td>
              <td><span class="status-open">OPEN</span></td>
              <td><b>{html.escape(r.service)}</b></td>
              <td>{r.latency_ms:.1f} ms</td>
              <td><code class="banner">{html.escape(r.banner or '—')}</code></td>
              <td>{adv_html}</td>
            </tr>
            """)

        table_content = "\n".join(rows_html) if rows_html else '<tr><td colspan="6" style="text-align:center;padding:30px;color:#888;">No open ports discovered.</td></tr>'

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PortScanner Report - {html.escape(self.target.raw_target)}</title>
  <style>
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f111a; color: #e0e6ed; padding: 24px; margin: 0; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .header {{ border-bottom: 1px solid #292d3e; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }}
    h1 {{ margin: 0; color: #00e5ff; font-size: 24px; }}
    .meta {{ color: #8892b0; font-size: 13px; margin-top: 4px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: #1a1c29; border: 1px solid #292d3e; border-radius: 10px; padding: 16px; text-align: center; }}
    .card-num {{ font-size: 26px; font-weight: bold; margin-top: 4px; }}
    .card-green {{ color: #00e676; }}
    .card-yellow {{ color: #ffd740; }}
    .card-dim {{ color: #8892b0; }}
    .search {{ margin-bottom: 16px; background: #121420; border: 1px solid #292d3e; color: #fff; padding: 10px 14px; border-radius: 8px; width: 300px; outline: none; }}
    table {{ width: 100%; border-collapse: collapse; background: #1a1c29; border-radius: 8px; overflow: hidden; border: 1px solid #292d3e; }}
    th {{ background: #121420; color: #8892b0; text-align: left; padding: 12px 16px; font-size: 12px; text-transform: uppercase; }}
    td {{ padding: 12px 16px; border-bottom: 1px solid #222638; font-size: 14px; }}
    tr:hover {{ background: rgba(0, 229, 255, 0.03); }}
    .port-badge {{ font-family: monospace; font-weight: bold; color: #00e5ff; background: rgba(0, 229, 255, 0.1); padding: 2px 8px; border-radius: 4px; }}
    .status-open {{ color: #00e676; font-weight: bold; font-size: 11px; background: rgba(0, 230, 118, 0.15); padding: 3px 8px; border-radius: 4px; }}
    .banner {{ color: #a6adc8; font-size: 12px; }}
    .advisory {{ color: #ffab40; font-size: 12px; }}
    .dim {{ color: #555; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>⚡ PortScanner Security Report</h1>
        <div class="meta">Target: <b>{html.escape(self.target.raw_target)}</b> ({self.target.ip}) | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
      </div>
      <div class="meta">Elapsed: <b>{self.elapsed_time}s</b> | Total: <b>{self.total_ports}</b> ports</div>
    </div>
    <div class="cards">
      <div class="card"><div style="font-size:12px;color:#8892b0;">OPEN PORTS</div><div class="card-num card-green">{len(self.open_ports)}</div></div>
      <div class="card"><div style="font-size:12px;color:#8892b0;">CLOSED PORTS</div><div class="card-num card-dim">{len(self.closed_ports)}</div></div>
      <div class="card"><div style="font-size:12px;color:#8892b0;">FILTERED PORTS</div><div class="card-num card-yellow">{len(self.filtered_ports)}</div></div>
      <div class="card"><div style="font-size:12px;color:#8892b0;">SCAN TIME</div><div class="card-num">{self.elapsed_time}s</div></div>
    </div>
    <input type="text" class="search" id="filter" placeholder="Filter ports or services..." oninput="filterRows()">
    <table id="tbl">
      <thead>
        <tr><th>Port</th><th>Status</th><th>Service</th><th>Latency</th><th>Banner / Version</th><th>Security Advisory</th></tr>
      </thead>
      <tbody>
        {table_content}
      </tbody>
    </table>
  </div>
  <script>
    function filterRows() {{
      const q = document.getElementById("filter").value.toLowerCase();
      const rows = document.querySelectorAll("#tbl tbody tr");
      rows.forEach(r => {{
        r.style.display = r.textContent.toLowerCase().includes(q) ? "" : "none";
      }});
    }}
  </script>
</body>
</html>
"""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        print(f"{Colors.GREEN}[*]{Colors.RESET} Scan results saved to HTML: {file_path}")

