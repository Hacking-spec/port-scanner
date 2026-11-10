"""
Web UI Dashboard for PortScanner.
Provides a modern, responsive browser-based single-page application (SPA)
powered by a lightweight built-in HTTP server with REST APIs.
"""

import json
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

from portscanner.aggregator import ResultAggregator
from portscanner.cli import parse_ports
from portscanner.engine import ThreadPoolEngine
from portscanner.probe import PortResult, SocketProbe
from portscanner.services import TOP_100_PORTS
from portscanner.target_resolver import ResolvedTarget, TargetResolver

HTML_DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PortScanner Pro - Web Dashboard</title>
  <style>
    :root {
      --bg: #0f111a;
      --card-bg: #1a1c29;
      --card-border: #292d3e;
      --accent-cyan: #00e5ff;
      --accent-green: #00e676;
      --accent-red: #ff5252;
      --accent-yellow: #ffd740;
      --text: #e0e6ed;
      --text-dim: #8892b0;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
    body { background-color: var(--bg); color: var(--text); min-height: 100vh; padding: 24px; }
    .container { max-width: 1200px; margin: 0 auto; }
    
    /* Header */
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--card-border); }
    .logo-group { display: flex; align-items: center; gap: 12px; }
    .logo-badge { background: linear-gradient(135deg, #00e5ff, #7c4dff); width: 42px; height: 42px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: bold; color: #fff; }
    h1 { font-size: 24px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
    .subtitle { font-size: 13px; color: var(--text-dim); }
    
    /* Cards */
    .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 20px; margin-bottom: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.3); }
    .card-title { font-size: 16px; font-weight: 600; color: var(--accent-cyan); margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    
    /* Form controls */
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
    .form-group { display: flex; flex-direction: column; gap: 6px; }
    label { font-size: 13px; font-weight: 600; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }
    input, select { background: #121420; border: 1px solid var(--card-border); color: #fff; padding: 10px 14px; border-radius: 8px; font-size: 14px; outline: none; transition: border-color 0.2s; }
    input:focus, select:focus { border-color: var(--accent-cyan); }
    
    .btn-group { display: flex; gap: 12px; margin-top: 20px; flex-wrap: wrap; }
    button { cursor: pointer; border: none; padding: 10px 20px; border-radius: 8px; font-size: 14px; font-weight: 600; display: inline-flex; align-items: center; gap: 8px; transition: transform 0.1s, opacity 0.2s; }
    button:active { transform: scale(0.98); }
    .btn-start { background: linear-gradient(135deg, #00e676, #00b0ff); color: #0f111a; }
    .btn-stop { background: var(--accent-red); color: #fff; }
    .btn-export { background: #232738; color: var(--text); border: 1px solid var(--card-border); }
    .btn-export:hover { border-color: var(--accent-cyan); color: #fff; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }

    /* Metrics Grid */
    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .metric-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 16px; text-align: center; }
    .metric-val { font-size: 28px; font-weight: 700; color: #fff; margin-top: 4px; }
    .metric-open { color: var(--accent-green); }
    .metric-closed { color: var(--text-dim); }
    .metric-filtered { color: var(--accent-yellow); }

    /* Progress bar */
    .progress-wrap { background: #121420; border-radius: 8px; height: 12px; overflow: hidden; margin-bottom: 12px; position: relative; border: 1px solid var(--card-border); }
    .progress-fill { background: linear-gradient(90deg, #00e5ff, #00e676); height: 100%; width: 0%; transition: width 0.2s ease; }
    .status-text { font-size: 13px; color: var(--text-dim); display: flex; justify-content: space-between; }

    /* Table */
    .table-controls { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .search-input { width: 280px; padding: 8px 12px; font-size: 13px; }
    .table-container { overflow-x: auto; max-height: 480px; border: 1px solid var(--card-border); border-radius: 8px; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
    th { background: #121420; color: var(--text-dim); font-size: 12px; font-weight: 600; text-transform: uppercase; padding: 12px 16px; position: sticky; top: 0; z-index: 2; border-bottom: 1px solid var(--card-border); }
    td { padding: 12px 16px; border-bottom: 1px solid #232738; }
    tr:hover { background: rgba(0, 229, 255, 0.04); }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .badge-open { background: rgba(0, 230, 118, 0.15); color: var(--accent-green); border: 1px solid rgba(0, 230, 118, 0.3); }
    .code { font-family: 'Consolas', monospace; color: var(--accent-cyan); font-weight: bold; }
    .banner-text { color: var(--text-dim); font-size: 13px; word-break: break-all; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-group">
        <div class="logo-badge">⚡</div>
        <div>
          <h1>PortScanner Pro</h1>
          <div class="subtitle">Multi-Threaded TCP Port Scanner & Service Detection Dashboard</div>
        </div>
      </div>
      <div id="conn-status" style="font-size: 13px; color: var(--accent-green);">● Engine Ready</div>
    </header>

    <!-- Scan Configuration -->
    <div class="card">
      <div class="card-title">🔍 Scan Target & Options</div>
      <div class="form-grid">
        <div class="form-group">
          <label>Target Host / IP</label>
          <input type="text" id="target" value="127.0.0.1" placeholder="e.g. 192.168.1.1 or scanme.nmap.org">
        </div>
        <div class="form-group">
          <label>Port Preset</label>
          <select id="preset" onchange="toggleCustomPorts()">
            <option value="top100">Top 100 Common Ports</option>
            <option value="top20">Top 20 Fast Scan</option>
            <option value="web">Web Ports (80, 443, 8080, 8443, 3000, 5000)</option>
            <option value="custom">Custom Port Range...</option>
          </select>
        </div>
        <div class="form-group" id="custom-group" style="display: none;">
          <label>Custom Ports</label>
          <input type="text" id="custom-ports" placeholder="e.g. 21,22,80,443 or 1-1024">
        </div>
        <div class="form-group">
          <label>Concurrency (Threads)</label>
          <input type="number" id="threads" value="100" min="1" max="500">
        </div>
        <div class="form-group">
          <label>Timeout (Seconds)</label>
          <input type="number" id="timeout" value="1.0" min="0.1" max="10" step="0.1">
        </div>
      </div>
      
      <div class="btn-group">
        <button id="btn-start" class="btn-start" onclick="startScan()">▶ Start Scan</button>
        <button id="btn-stop" class="btn-stop" onclick="stopScan()" disabled>⏹ Stop Scan</button>
        <button class="btn-export" onclick="downloadExport('json')">💾 Download JSON</button>
        <button class="btn-export" onclick="downloadExport('txt')">📄 Download Text</button>
      </div>
    </div>

    <!-- Live Progress -->
    <div class="card" style="padding-bottom: 16px;">
      <div class="progress-wrap">
        <div class="progress-fill" id="progress-bar"></div>
      </div>
      <div class="status-text">
        <span id="status-label">Status: Idle</span>
        <span id="percent-label">0%</span>
      </div>
    </div>

    <!-- Metrics Cards -->
    <div class="metrics-grid">
      <div class="metric-card">
        <div style="font-size: 12px; color: var(--text-dim);">OPEN PORTS</div>
        <div class="metric-val metric-open" id="stat-open">0</div>
      </div>
      <div class="metric-card">
        <div style="font-size: 12px; color: var(--text-dim);">CLOSED PORTS</div>
        <div class="metric-val metric-closed" id="stat-closed">0</div>
      </div>
      <div class="metric-card">
        <div style="font-size: 12px; color: var(--text-dim);">FILTERED PORTS</div>
        <div class="metric-val metric-filtered" id="stat-filtered">0</div>
      </div>
      <div class="metric-card">
        <div style="font-size: 12px; color: var(--text-dim);">TIME ELAPSED</div>
        <div class="metric-val" id="stat-time">0.0s</div>
      </div>
    </div>

    <!-- Discovered Open Ports Table -->
    <div class="card">
      <div class="table-controls">
        <div class="card-title" style="margin-bottom: 0;">📋 Discovered Services</div>
        <input type="text" class="search-input" id="search" placeholder="Filter by port or service..." oninput="filterTable()">
      </div>
      <div class="table-container">
        <table id="ports-table">
          <thead>
            <tr>
              <th style="width: 100px;">Port</th>
              <th style="width: 100px;">State</th>
              <th style="width: 200px;">Service</th>
              <th style="width: 120px;">Latency</th>
              <th>Banner / Fingerprint</th>
            </tr>
          </thead>
          <tbody id="ports-body">
            <tr>
              <td colspan="5" style="text-align: center; color: var(--text-dim); padding: 32px;">
                No scan results yet. Enter a target and click "Start Scan".
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    let pollInterval = null;
    let allOpenPorts = [];

    function toggleCustomPorts() {
      const preset = document.getElementById("preset").value;
      document.getElementById("custom-group").style.display = preset === "custom" ? "flex" : "none";
    }

    async function startScan() {
      const target = document.getElementById("target").value.trim();
      if (!target) {
        alert("Please enter a target host or IP.");
        return;
      }

      let portSpec = document.getElementById("preset").value;
      let customPorts = document.getElementById("custom-ports").value.trim();
      const threads = parseInt(document.getElementById("threads").value) || 100;
      const timeout = parseFloat(document.getElementById("timeout").value) || 1.0;

      document.getElementById("btn-start").disabled = true;
      document.getElementById("btn-stop").disabled = false;
      document.getElementById("ports-body").innerHTML = "";
      allOpenPorts = [];

      try {
        const res = await fetch("/api/scan/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target: target,
            preset: portSpec,
            custom_ports: customPorts,
            threads: threads,
            timeout: timeout,
            banner: true
          })
        });

        const data = await res.json();
        if (data.error) {
          alert("Error: " + data.error);
          document.getElementById("btn-start").disabled = false;
          document.getElementById("btn-stop").disabled = true;
          return;
        }

        document.getElementById("status-label").textContent = `Scanning ${data.target_ip} (${data.total_ports} ports)...`;
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(pollProgress, 250);
      } catch (err) {
        alert("Network error: " + err);
        document.getElementById("btn-start").disabled = false;
        document.getElementById("btn-stop").disabled = true;
      }
    }

    async function pollProgress() {
      try {
        const res = await fetch("/api/scan/progress");
        const data = await res.json();

        // Update progress bar
        const percent = data.total > 0 ? (data.completed / data.total) * 100 : 0;
        document.getElementById("progress-bar").style.width = percent.toFixed(1) + "%";
        document.getElementById("percent-label").textContent = percent.toFixed(1) + `% (${data.completed}/${data.total})`;

        // Metrics
        document.getElementById("stat-open").textContent = data.open_count;
        document.getElementById("stat-closed").textContent = data.closed_count;
        document.getElementById("stat-filtered").textContent = data.filtered_count;
        document.getElementById("stat-time").textContent = data.elapsed.toFixed(1) + "s";

        // Render open ports
        if (data.open_ports && data.open_ports.length > allOpenPorts.length) {
          allOpenPorts = data.open_ports;
          renderTable(allOpenPorts);
        }

        if (!data.is_running && data.completed >= data.total) {
          clearInterval(pollInterval);
          document.getElementById("btn-start").disabled = false;
          document.getElementById("btn-stop").disabled = true;
          document.getElementById("status-label").textContent = `Scan complete in ${data.elapsed.toFixed(1)}s! Found ${data.open_count} open port(s).`;
        }
      } catch (err) {}
    }

    async function stopScan() {
      await fetch("/api/scan/stop", { method: "POST" });
      document.getElementById("status-label").textContent = "Scan stopped.";
      document.getElementById("btn-start").disabled = false;
      document.getElementById("btn-stop").disabled = true;
      if (pollInterval) clearInterval(pollInterval);
    }

    function renderTable(ports) {
      const tbody = document.getElementById("ports-body");
      if (!ports || ports.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 32px;">No open ports found.</td></tr>`;
        return;
      }

      tbody.innerHTML = ports.map(p => `
        <tr>
          <td class="code">${p.port}/tcp</td>
          <td><span class="badge badge-open">OPEN</span></td>
          <td><b>${escapeHtml(p.service)}</b></td>
          <td>${p.latency_ms} ms</td>
          <td class="banner-text">${escapeHtml(p.banner || "—")}</td>
        </tr>
      `).join("");
    }

    function filterTable() {
      const q = document.getElementById("search").value.toLowerCase();
      const filtered = allOpenPorts.filter(p => 
        String(p.port).includes(q) || (p.service && p.service.toLowerCase().includes(q)) || (p.banner && p.banner.toLowerCase().includes(q))
      );
      renderTable(filtered);
    }

    function downloadExport(type) {
      window.open(`/api/scan/export?format=${type}`, "_blank");
    }

    function escapeHtml(text) {
      return text.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[m]);
    }
  </script>
</body>
</html>
"""


class WebScanState:
    """Thread-safe state manager for web scans."""
    def __init__(self):
        self.lock = threading.Lock()
        self.is_running = False
        self.target_ip = ""
        self.target_raw = ""
        self.total_ports = 0
        self.completed_ports = 0
        self.open_ports: List[Dict[str, Any]] = []
        self.closed_count = 0
        self.filtered_count = 0
        self.start_time = 0.0
        self.end_time = 0.0
        self.stop_event = threading.Event()
        self.current_aggregator: Optional[ResultAggregator] = None


STATE = WebScanState()


class PortScannerHttpHandler(BaseHTTPRequestHandler):
    """Handles REST APIs and serves the Dashboard UI."""

    def log_message(self, format, *args):
        # Suppress noisy HTTP server logs in console
        pass

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)

        if url.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
            return

        elif url.path == "/api/scan/progress":
            with STATE.lock:
                elapsed = (time.time() - STATE.start_time) if STATE.is_running else (STATE.end_time - STATE.start_time)
                data = {
                    "is_running": STATE.is_running,
                    "target_ip": STATE.target_ip,
                    "total": STATE.total_ports,
                    "completed": STATE.completed_ports,
                    "open_count": len(STATE.open_ports),
                    "closed_count": STATE.closed_count,
                    "filtered_count": STATE.filtered_count,
                    "elapsed": max(0.0, elapsed),
                    "open_ports": list(STATE.open_ports)
                }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        elif url.path == "/api/scan/export":
            query = urllib.parse.parse_qs(url.query)
            fmt = query.get("format", ["json"])[0]

            with STATE.lock:
                agg = STATE.current_aggregator

            if not agg:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"No scan completed to export.")
                return

            if fmt == "json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition", "attachment; filename=scan_results.json")
                self.end_headers()
                self.wfile.write(json.dumps(agg.to_dict(), indent=2).encode("utf-8"))
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Disposition", "attachment; filename=scan_results.txt")
                self.end_headers()
                # Render text format
                import io
                buf = io.StringIO()
                buf.write(f"# Target: {agg.target.raw_target} ({agg.target.ip})\n")
                buf.write(f"{'PORT':<10} {'STATE':<8} {'SERVICE':<28} {'LATENCY':<10} {'BANNER'}\n")
                buf.write("-" * 80 + "\n")
                for r in sorted(agg.open_ports, key=lambda x: x.port):
                    buf.write(f"{r.port}/tcp".ljust(10) + f"{r.state.lower()}".ljust(8) + f"{r.service}".ljust(28) + f"{r.latency_ms}ms".ljust(10) + f"{r.banner or '—'}\n")
                self.wfile.write(buf.getvalue().encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)

        if url.path == "/api/scan/start":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            params = json.loads(body) if body else {}

            target_str = params.get("target", "127.0.0.1").strip()
            preset = params.get("preset", "top100")
            custom_ports = params.get("custom_ports", "")
            threads = int(params.get("threads", 100))
            timeout = float(params.get("timeout", 1.0))
            banner = bool(params.get("banner", True))

            try:
                if preset == "top100":
                    ports = list(TOP_100_PORTS)
                elif preset == "top20":
                    ports = list(TOP_100_PORTS[:20])
                elif preset == "web":
                    ports = [80, 443, 3000, 5000, 8000, 8080, 8443, 8888]
                else:
                    ports = parse_ports(custom_ports)
            except Exception as e:
                self._send_json({"error": f"Invalid ports: {str(e)}"}, 400)
                return

            resolved = TargetResolver.resolve(target_str)
            if not resolved.is_valid:
                self._send_json({"error": resolved.error_message or "Failed to resolve target"}, 400)
                return

            with STATE.lock:
                if STATE.is_running:
                    self._send_json({"error": "A scan is already in progress. Please stop it first."}, 409)
                    return
                STATE.is_running = True
                STATE.target_raw = target_str
                STATE.target_ip = resolved.ip
                STATE.total_ports = len(ports)
                STATE.completed_ports = 0
                STATE.open_ports = []
                STATE.closed_count = 0
                STATE.filtered_count = 0
                STATE.start_time = time.time()
                STATE.end_time = 0.0
                STATE.stop_event.clear()

            # Start worker thread
            worker = threading.Thread(
                target=self._run_scan_background,
                args=(resolved, ports, threads, timeout, banner),
                daemon=True
            )
            worker.start()

            self._send_json({
                "status": "started",
                "target_ip": resolved.ip,
                "total_ports": len(ports)
            })
            return

        elif url.path == "/api/scan/stop":
            with STATE.lock:
                STATE.stop_event.set()
                STATE.is_running = False
                STATE.end_time = time.time()
            self._send_json({"status": "stopped"})
            return

        self.send_response(404)
        self.end_headers()

    def _send_json(self, data: Dict[str, Any], status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    @staticmethod
    def _run_scan_background(resolved: ResolvedTarget, ports: List[int], threads: int, timeout: float, banner: bool):
        aggregator = ResultAggregator(target=resolved, total_ports=len(ports), no_color=True)
        probe = SocketProbe(timeout=timeout, banner_grab=banner)

        with STATE.lock:
            STATE.current_aggregator = aggregator

        engine = ThreadPoolEngine(
            target_ip=resolved.ip,
            ports=ports,
            probe=probe,
            aggregator=aggregator,
            num_threads=threads,
            show_progress=False
        )

        orig_add = aggregator.add_result
        def hooked_add_result(res: PortResult, live_notify: bool = False):
            orig_add(res, live_notify=False)
            with STATE.lock:
                if res.state == "OPEN":
                    STATE.open_ports.append({
                        "port": res.port,
                        "service": res.service,
                        "latency_ms": res.latency_ms,
                        "banner": res.banner
                    })
                elif res.state == "FILTERED":
                    STATE.filtered_count += 1
                else:
                    STATE.closed_count += 1
                STATE.completed_ports += 1

        aggregator.add_result = hooked_add_result

        try:
            engine.run()
        finally:
            with STATE.lock:
                STATE.is_running = False
                STATE.end_time = time.time()
                STATE.completed_ports = STATE.total_ports


def launch_web_ui(host: str = "127.0.0.1", port: int = 5000):
    """Start local web server and serve the dashboard."""
    server_address = (host, port)
    try:
        httpd = HTTPServer(server_address, PortScannerHttpHandler)
    except OSError:
        # Try next port if 5000 is occupied
        port = 8080
        server_address = (host, port)
        httpd = HTTPServer(server_address, PortScannerHttpHandler)

    url = f"http://{host}:{port}"
    print(f"\n⚡ PortScanner Web Dashboard running at: {url}")
    print("Press Ctrl+C to stop the web server.\n")

    # Attempt to auto-open in browser if possible
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb dashboard stopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    launch_web_ui()

