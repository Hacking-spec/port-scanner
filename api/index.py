import os
import sys
import time
import threading
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from portscanner.aggregator import ResultAggregator
from portscanner.cli import parse_ports
from portscanner.engine import ThreadPoolEngine
from portscanner.probe import PortResult, SocketProbe
from portscanner.services import TOP_100_PORTS
from portscanner.target_resolver import ResolvedTarget, TargetResolver
from portscanner.web_ui import HTML_DASHBOARD, STATE

app = FastAPI(title="PortScanner Web Dashboard")


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    return HTMLResponse(content=HTML_DASHBOARD)


@app.get("/api/scan/progress")
async def get_progress():
    with STATE.lock:
        elapsed = (time.time() - STATE.start_time) if STATE.is_running else (STATE.end_time - STATE.start_time)
        return {
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


@app.post("/api/scan/start")
async def start_scan(request: Request):
    params = await request.json()
    target_str = params.get("target", "127.0.0.1").strip()
    preset = params.get("preset", "top100")
    custom_ports = params.get("custom_ports", "")
    threads = min(int(params.get("threads", 100)), 200)
    timeout = max(0.1, min(float(params.get("timeout", 1.0)), 5.0))
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
        return JSONResponse(status_code=400, content={"error": f"Invalid ports: {str(e)}"})

    resolved = TargetResolver.resolve(target_str)
    if not resolved.is_valid:
        return JSONResponse(status_code=400, content={"error": resolved.error_message or "Failed to resolve target"})

    with STATE.lock:
        if STATE.is_running:
            return JSONResponse(status_code=409, content={"error": "A scan is already in progress. Please stop it first."})
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

    worker = threading.Thread(
        target=_run_scan_worker,
        args=(resolved, ports, threads, timeout, banner),
        daemon=True
    )
    worker.start()

    return {"status": "started", "target_ip": resolved.ip, "total_ports": len(ports)}


@app.post("/api/scan/stop")
async def stop_scan():
    with STATE.lock:
        STATE.stop_event.set()
        STATE.is_running = False
        STATE.end_time = time.time()
    return {"status": "stopped"}


@app.get("/api/scan/export")
async def export_results(format: str = "json"):
    with STATE.lock:
        agg = STATE.current_aggregator

    if not agg:
        return Response(status_code=400, content="No scan results available.")

    if format == "json":
        import json
        return JSONResponse(
            content=agg.to_dict(),
            headers={"Content-Disposition": "attachment; filename=scan_results.json"}
        )
    else:
        import io
        buf = io.StringIO()
        buf.write(f"# Target: {agg.target.raw_target} ({agg.target.ip})\n")
        buf.write(f"{'PORT':<10} {'STATE':<8} {'SERVICE':<28} {'LATENCY':<10} {'BANNER'}\n")
        buf.write("-" * 80 + "\n")
        for r in sorted(agg.open_ports, key=lambda x: x.port):
            buf.write(f"{r.port}/tcp".ljust(10) + f"{r.state.lower()}".ljust(8) + f"{r.service}".ljust(28) + f"{r.latency_ms}ms".ljust(10) + f"{r.banner or '—'}\n")
        return PlainTextResponse(
            content=buf.getvalue(),
            headers={"Content-Disposition": "attachment; filename=scan_results.txt"}
        )


def _run_scan_worker(resolved: ResolvedTarget, ports: List[int], threads: int, timeout: float, banner: bool):
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
