"""
Desktop GUI Module for PortScanner using Tkinter.
Provides a modern dark-themed graphical interface for configuring scans,
viewing real-time open port discoveries, and exporting reports.
"""

import json
import os
import queue
import sys
import threading
import time
from tkinter import messagebox, ttk
import tkinter as tk
from typing import List, Optional

from portscanner.aggregator import ResultAggregator
from portscanner.cli import parse_ports
from portscanner.engine import ThreadPoolEngine
from portscanner.probe import PortResult, SocketProbe
from portscanner.services import TOP_100_PORTS
from portscanner.target_resolver import ResolvedTarget, TargetResolver


# Theme color palette
BG_DARK = "#181825"
BG_CARD = "#1e1e2e"
BG_INPUT = "#313244"
TEXT_MAIN = "#cdd6f4"
TEXT_DIM = "#a6adc8"
ACCENT_CYAN = "#89dceb"
ACCENT_GREEN = "#a6e3a1"
ACCENT_RED = "#f38ba8"
ACCENT_YELLOW = "#f9e2af"
ACCENT_BLUE = "#89b4fa"


class PortScannerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PortScanner Pro - Graphical Interface")
        self.root.geometry("980x720")
        self.root.minsize(800, 600)
        self.root.configure(bg=BG_DARK)

        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._gui_queue: queue.Queue = queue.Queue()
        self._is_scanning = False
        self._current_aggregator: Optional[ResultAggregator] = None

        self._setup_styles()
        self._build_ui()
        self._poll_gui_queue()

    def _setup_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Configure Treeview styling
        style.configure(
            "Treeview",
            background=BG_CARD,
            foreground=TEXT_MAIN,
            fieldbackground=BG_CARD,
            rowheight=26,
            font=("Segoe UI", 10)
        )
        style.configure(
            "Treeview.Heading",
            background=BG_INPUT,
            foreground=TEXT_MAIN,
            font=("Segoe UI", 10, "bold")
        )
        style.map("Treeview", background=[("selected", "#45475a")], foreground=[("selected", "#ffffff")])

        # Progress bar
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=BG_INPUT,
            bordercolor=BG_DARK,
            background=ACCENT_CYAN,
            lightcolor=ACCENT_CYAN,
            darkcolor=ACCENT_CYAN
        )

    def _build_ui(self):
        # Header banner frame
        header_frame = tk.Frame(self.root, bg=BG_DARK, pady=12, padx=16)
        header_frame.pack(fill=tk.X)

        title_label = tk.Label(
            header_frame,
            text="⚡ PortScanner Pro",
            font=("Segoe UI", 18, "bold"),
            bg=BG_DARK,
            fg=ACCENT_CYAN
        )
        title_label.pack(side=tk.LEFT)

        subtitle_label = tk.Label(
            header_frame,
            text="Multi-Threaded TCP Port Scanner & Service Detection Engine",
            font=("Segoe UI", 10),
            bg=BG_DARK,
            fg=TEXT_DIM
        )
        subtitle_label.pack(side=tk.LEFT, padx=15, pady=6)

        # Main configuration card
        config_card = tk.LabelFrame(
            self.root,
            text=" Scan Configuration ",
            font=("Segoe UI", 11, "bold"),
            bg=BG_CARD,
            fg=ACCENT_CYAN,
            padx=16,
            pady=12,
            bd=1,
            relief=tk.GROOVE
        )
        config_card.pack(fill=tk.X, padx=16, pady=6)

        # Row 1: Target Host and Port Preset
        r1 = tk.Frame(config_card, bg=BG_CARD)
        r1.pack(fill=tk.X, pady=4)

        tk.Label(r1, text="Target Host / IP:", font=("Segoe UI", 10, "bold"), bg=BG_CARD, fg=TEXT_MAIN).pack(side=tk.LEFT)
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.target_entry = tk.Entry(
            r1,
            textvariable=self.target_var,
            font=("Segoe UI", 10),
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN,
            width=28,
            bd=1,
            relief=tk.FLAT
        )
        self.target_entry.pack(side=tk.LEFT, padx=(10, 25))

        tk.Label(r1, text="Ports Spec / Preset:", font=("Segoe UI", 10, "bold"), bg=BG_CARD, fg=TEXT_MAIN).pack(side=tk.LEFT)
        self.port_preset_var = tk.StringVar(value="Top 100 Common Ports")
        self.port_combo = ttk.Combobox(
            r1,
            textvariable=self.port_preset_var,
            values=[
                "Top 100 Common Ports",
                "Top 20 Common Ports",
                "Web Ports (80,443,8080,8443,3000,5000)",
                "All Well-Known (1-1024)",
                "Custom..."
            ],
            state="readonly",
            width=26
        )
        self.port_combo.pack(side=tk.LEFT, padx=10)
        self.port_combo.bind("<<ComboboxSelected>>", self._on_preset_change)

        self.custom_port_var = tk.StringVar(value="")
        self.custom_port_entry = tk.Entry(
            r1,
            textvariable=self.custom_port_var,
            font=("Segoe UI", 10),
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN,
            width=20,
            state=tk.DISABLED
        )
        self.custom_port_entry.pack(side=tk.LEFT, padx=8)

        # Row 2: Advanced parameters (Threads, Timeout, Banner Grab)
        r2 = tk.Frame(config_card, bg=BG_CARD)
        r2.pack(fill=tk.X, pady=6)

        tk.Label(r2, text="Threads:", font=("Segoe UI", 10), bg=BG_CARD, fg=TEXT_MAIN).pack(side=tk.LEFT)
        self.threads_var = tk.IntVar(value=100)
        self.threads_spin = tk.Spinbox(
            r2,
            from_=1,
            to=500,
            textvariable=self.threads_var,
            width=5,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN
        )
        self.threads_spin.pack(side=tk.LEFT, padx=(6, 20))

        tk.Label(r2, text="Timeout (s):", font=("Segoe UI", 10), bg=BG_CARD, fg=TEXT_MAIN).pack(side=tk.LEFT)
        self.timeout_var = tk.DoubleVar(value=1.0)
        self.timeout_spin = tk.Spinbox(
            r2,
            from_=0.1,
            to=10.0,
            increment=0.1,
            textvariable=self.timeout_var,
            width=5,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN
        )
        self.timeout_spin.pack(side=tk.LEFT, padx=(6, 20))

        self.banner_var = tk.BooleanVar(value=True)
        self.banner_check = tk.Checkbutton(
            r2,
            text="Service Detection & Banner Grabbing",
            variable=self.banner_var,
            bg=BG_CARD,
            fg=TEXT_MAIN,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            activeforeground=TEXT_MAIN,
            font=("Segoe UI", 10)
        )
        self.banner_check.pack(side=tk.LEFT, padx=10)

        # Action Buttons Frame
        btn_frame = tk.Frame(config_card, bg=BG_CARD)
        btn_frame.pack(fill=tk.X, pady=(8, 2))

        self.start_btn = tk.Button(
            btn_frame,
            text="▶  Start Scan",
            font=("Segoe UI", 10, "bold"),
            bg="#2e7d32",
            fg="#ffffff",
            activebackground="#1b5e20",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=18,
            pady=4,
            cursor="hand2",
            command=self._start_scan
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(
            btn_frame,
            text="⏹  Stop Scan",
            font=("Segoe UI", 10, "bold"),
            bg="#c62828",
            fg="#ffffff",
            activebackground="#b71c1c",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=18,
            pady=4,
            state=tk.DISABLED,
            cursor="hand2",
            command=self._stop_scan
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = tk.Button(
            btn_frame,
            text="🧹 Clear Table",
            font=("Segoe UI", 10),
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            relief=tk.FLAT,
            padx=12,
            pady=4,
            cursor="hand2",
            command=self._clear_results
        )
        self.clear_btn.pack(side=tk.LEFT, padx=15)

        self.export_json_btn = tk.Button(
            btn_frame,
            text="💾 Save JSON",
            font=("Segoe UI", 10),
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            relief=tk.FLAT,
            padx=12,
            pady=4,
            cursor="hand2",
            command=self._export_json
        )
        self.export_json_btn.pack(side=tk.RIGHT, padx=5)

        self.export_txt_btn = tk.Button(
            btn_frame,
            text="📄 Save Text",
            font=("Segoe UI", 10),
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            relief=tk.FLAT,
            padx=12,
            pady=4,
            cursor="hand2",
            command=self._export_txt
        )
        self.export_txt_btn.pack(side=tk.RIGHT, padx=5)

        # Progress and status bar card
        status_card = tk.Frame(self.root, bg=BG_DARK, padx=16, pady=4)
        status_card.pack(fill=tk.X)

        self.progress_bar = ttk.Progressbar(
            status_card,
            orient="horizontal",
            mode="determinate",
            style="Horizontal.TProgressbar"
        )
        self.progress_bar.pack(fill=tk.X, pady=(0, 4))

        metrics_frame = tk.Frame(status_card, bg=BG_DARK)
        metrics_frame.pack(fill=tk.X)

        self.status_label = tk.Label(
            metrics_frame,
            text="Status: Ready",
            font=("Segoe UI", 10, "bold"),
            bg=BG_DARK,
            fg=TEXT_MAIN
        )
        self.status_label.pack(side=tk.LEFT)

        self.metrics_label = tk.Label(
            metrics_frame,
            text="Open: 0 | Closed: 0 | Filtered: 0 | Time: 0.0s",
            font=("Segoe UI", 10),
            bg=BG_DARK,
            fg=ACCENT_YELLOW
        )
        self.metrics_label.pack(side=tk.RIGHT)

        # Results Treeview Table
        table_frame = tk.Frame(self.root, bg=BG_DARK, padx=16, pady=6)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("port", "state", "service", "latency", "banner")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="extended"
        )

        self.tree.heading("port", text="PORT")
        self.tree.heading("state", text="STATE")
        self.tree.heading("service", text="SERVICE")
        self.tree.heading("latency", text="LATENCY")
        self.tree.heading("banner", text="BANNER / VERSION INFO")

        self.tree.column("port", width=90, anchor=tk.CENTER)
        self.tree.column("state", width=80, anchor=tk.CENTER)
        self.tree.column("service", width=180, anchor=tk.W)
        self.tree.column("latency", width=90, anchor=tk.CENTER)
        self.tree.column("banner", width=420, anchor=tk.W)

        # Scrollbars
        v_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

    def _on_preset_change(self, event=None):
        val = self.port_preset_var.get()
        if val == "Custom...":
            self.custom_port_entry.configure(state=tk.NORMAL)
            self.custom_port_entry.focus_set()
        else:
            self.custom_port_entry.configure(state=tk.DISABLED)

    def _get_ports_to_scan(self) -> List[int]:
        preset = self.port_preset_var.get()
        if preset == "Top 100 Common Ports":
            return list(TOP_100_PORTS)
        elif preset == "Top 20 Common Ports":
            return list(TOP_100_PORTS[:20])
        elif preset == "Web Ports (80,443,8080,8443,3000,5000)":
            return [80, 443, 3000, 5000, 8000, 8080, 8443, 8888]
        elif preset == "All Well-Known (1-1024)":
            return list(range(1, 1025))
        else:
            # Custom
            raw = self.custom_port_var.get().strip()
            if not raw:
                raise ValueError("Please enter a custom port or range (e.g. '80,443' or '1-500').")
            return parse_ports(raw)

    def _start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target host or IP address.")
            return

        try:
            ports = self._get_ports_to_scan()
        except ValueError as e:
            messagebox.showerror("Invalid Ports", str(e))
            return

        threads = max(1, self.threads_var.get())
        timeout = max(0.1, self.timeout_var.get())
        banner = self.banner_var.get()

        self._clear_results()
        self._is_scanning = True
        self._stop_event.clear()
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.status_label.configure(text=f"Resolving target '{target}'...", fg=ACCENT_CYAN)
        self.progress_bar["value"] = 0
        self.progress_bar["maximum"] = len(ports)

        # Launch scanning in a background worker thread
        self._scan_thread = threading.Thread(
            target=self._run_scan_thread,
            args=(target, ports, threads, timeout, banner),
            daemon=True
        )
        self._scan_thread.start()

    def _run_scan_thread(self, target_str: str, ports: List[int], threads: int, timeout: float, banner: bool):
        resolved = TargetResolver.resolve(target_str)
        if not resolved.is_valid:
            self._gui_queue.put(("error", resolved.error_message or "Failed to resolve target."))
            return

        self._gui_queue.put(("status", f"Scanning {resolved.ip} ({len(ports)} ports)..."))

        aggregator = ResultAggregator(target=resolved, total_ports=len(ports), no_color=True)
        self._current_aggregator = aggregator
        probe = SocketProbe(timeout=timeout, banner_grab=banner)

        # ThreadPoolEngine with real-time UI queue callbacks
        engine = ThreadPoolEngine(
            target_ip=resolved.ip,
            ports=ports,
            probe=probe,
            aggregator=aggregator,
            num_threads=threads,
            show_progress=False
        )

        def poll_engine_progress():
            start_t = time.time()
            total = len(ports)
            while self._is_scanning and not self._stop_event.is_set():
                done = engine._completed_count
                open_cnt = len(aggregator.open_ports)
                closed_cnt = len(aggregator.closed_ports)
                filtered_cnt = len(aggregator.filtered_ports)
                elapsed = time.time() - start_t

                self._gui_queue.put(("progress", done, total, open_cnt, closed_cnt, filtered_cnt, elapsed))
                if done >= total:
                    break
                time.sleep(0.1)

        progress_thread = threading.Thread(target=poll_engine_progress, daemon=True)
        progress_thread.start()

        # Wrap aggregator add_result to push directly to treeview
        orig_add = aggregator.add_result
        def hooked_add_result(res: PortResult, live_notify: bool = False):
            orig_add(res, live_notify=False)
            if res.state == "OPEN":
                self._gui_queue.put(("open_port", res))

        aggregator.add_result = hooked_add_result

        try:
            engine.run()
        finally:
            self._gui_queue.put(("finished", aggregator))

    def _poll_gui_queue(self):
        try:
            while True:
                msg = self._gui_queue.get_nowait()
                mtype = msg[0]

                if mtype == "open_port":
                    res: PortResult = msg[1]
                    self.tree.insert(
                        "",
                        tk.END,
                        values=(
                            f"{res.port}/tcp",
                            "OPEN",
                            res.service,
                            f"{res.latency_ms} ms",
                            res.banner or "—"
                        )
                    )
                elif mtype == "progress":
                    _, done, total, open_cnt, closed_cnt, filtered_cnt, elapsed = msg
                    self.progress_bar["value"] = done
                    self.metrics_label.configure(
                        text=f"Open: {open_cnt} | Closed: {closed_cnt} | Filtered: {filtered_cnt} | Time: {elapsed:.1f}s"
                    )
                elif mtype == "status":
                    self.status_label.configure(text=msg[1], fg=ACCENT_CYAN)
                elif mtype == "error":
                    self.status_label.configure(text=f"Error: {msg[1]}", fg=ACCENT_RED)
                    messagebox.showerror("Scan Error", msg[1])
                    self._on_scan_completed()
                elif mtype == "finished":
                    agg: ResultAggregator = msg[1]
                    self.status_label.configure(
                        text=f"Scan Finished! Found {len(agg.open_ports)} open port(s) in {agg.elapsed_time}s",
                        fg=ACCENT_GREEN
                    )
                    self.progress_bar["value"] = self.progress_bar["maximum"]
                    self._on_scan_completed()

        except queue.Empty:
            pass

        self.root.after(100, self._poll_gui_queue)

    def _stop_scan(self):
        if self._is_scanning:
            self._stop_event.set()
            self._is_scanning = False
            self.status_label.configure(text="Scan stopped by user.", fg=ACCENT_YELLOW)
            self._on_scan_completed()

    def _on_scan_completed(self):
        self._is_scanning = False
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)

    def _clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.progress_bar["value"] = 0
        self.metrics_label.configure(text="Open: 0 | Closed: 0 | Filtered: 0 | Time: 0.0s")
        self.status_label.configure(text="Status: Ready", fg=TEXT_MAIN)

    def _export_json(self):
        if not self._current_aggregator or not self._current_aggregator.open_ports:
            messagebox.showinfo("Export", "No open port results to export.")
            return

        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Export Results as JSON"
        )
        if path:
            self._current_aggregator.export_json(path)
            messagebox.showinfo("Export Success", f"Scan results successfully exported to:\n{path}")

    def _export_txt(self):
        if not self._current_aggregator or not self._current_aggregator.open_ports:
            messagebox.showinfo("Export", "No open port results to export.")
            return

        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Export Results as Text"
        )
        if path:
            self._current_aggregator.export_txt(path)
            messagebox.showinfo("Export Success", f"Scan results successfully exported to:\n{path}")


def launch_gui():
    """Launch Desktop GUI application."""
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()

