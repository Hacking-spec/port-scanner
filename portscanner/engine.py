"""
ThreadPool Engine module for PortScanner.
Manages worker thread pool, work queue, real-time progress rendering, and graceful cancellation.
"""

import queue
import sys
import threading
import time
from typing import List, Optional

from portscanner.aggregator import Colors, ResultAggregator
from portscanner.probe import SocketProbe


class ThreadPoolEngine:
    """
    Coordinates multi-threaded port scanning using a synchronized work queue.
    """

    def __init__(
        self,
        target_ip: str,
        ports: List[int],
        probe: SocketProbe,
        aggregator: ResultAggregator,
        num_threads: int = 50,
        show_progress: bool = True
    ):
        self.target_ip = target_ip
        self.ports = ports
        self.probe = probe
        self.aggregator = aggregator
        self.num_threads = min(num_threads, len(ports)) if ports else 1
        self.show_progress = show_progress and sys.stdout.isatty()

        self._work_queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._workers: List[threading.Thread] = []
        self._completed_count = 0
        self._count_lock = threading.Lock()

    def run(self) -> None:
        """
        Populate the work queue, launch worker threads, and monitor progress until completion.
        """
        total_ports = len(self.ports)
        if total_ports == 0:
            return

        # Populate queue
        for port in self.ports:
            self._work_queue.put(port)

        self.aggregator.start()

        # Spawn worker threads
        for i in range(self.num_threads):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"ScannerWorker-{i+1}",
                daemon=True
            )
            worker.start()
            self._workers.append(worker)

        # Monitor progress in the main thread
        try:
            while not self._work_queue.empty() or self._completed_count < total_ports:
                if self._stop_event.is_set():
                    break
                if self.show_progress:
                    self._render_progress(total_ports)
                time.sleep(0.08)

            # Wait for all workers to finish remaining tasks
            self._work_queue.join()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user (Ctrl+C). Terminating workers...{Colors.RESET}")
            self._stop_event.set()
            # Clear remaining queue items so workers can exit
            while not self._work_queue.empty():
                try:
                    self._work_queue.get_nowait()
                    self._work_queue.task_done()
                except queue.Empty:
                    break

        finally:
            self._stop_event.set()
            # Clear progress line if shown
            if self.show_progress:
                sys.stdout.write("\r" + " " * 80 + "\r")
                sys.stdout.flush()
            self.aggregator.finish()

    def _worker_loop(self) -> None:
        """Worker thread entry point: pulls ports from queue and invokes probe."""
        while not self._stop_event.is_set():
            try:
                port = self._work_queue.get(timeout=0.2)
            except queue.Empty:
                break

            try:
                if not self._stop_event.is_set():
                    result = self.probe.probe(self.target_ip, port)
                    self.aggregator.add_result(result, live_notify=True)
            except Exception:
                pass
            finally:
                with self._count_lock:
                    self._completed_count += 1
                self._work_queue.task_done()

    def _render_progress(self, total: int) -> None:
        """Render a single-line terminal progress bar."""
        with self._count_lock:
            done = self._completed_count

        percent = (done / total) * 100 if total > 0 else 100
        bar_length = 24
        filled_length = int(bar_length * done // total) if total > 0 else bar_length
        bar = "=" * filled_length + ">" * (1 if filled_length < bar_length else 0)
        bar = bar.ljust(bar_length)

        open_count = len(self.aggregator.open_ports)
        line = (
            f"\r{Colors.CYAN}Progress: [{bar}] {percent:5.1f}% "
            f"({done}/{total}) | Open: {Colors.GREEN}{open_count}{Colors.CYAN}{Colors.RESET}"
        )
        sys.stdout.write(line)
        sys.stdout.flush()

