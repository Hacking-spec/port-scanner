"""
Comprehensive test suite for PortScanner modules:
- Target Resolver
- Port Parsing
- Socket Probe & Banner Grabbing
- Result Aggregator & JSON Export
- ThreadPool Engine
"""

import json
import os
import socket
import tempfile
import threading
import time
import unittest

from portscanner.aggregator import ResultAggregator
from portscanner.cli import parse_ports
from portscanner.engine import ThreadPoolEngine
from portscanner.probe import PortResult, SocketProbe
from portscanner.services import TOP_100_PORTS, get_service_name
from portscanner.target_resolver import ResolvedTarget, TargetResolver


class TestTargetResolver(unittest.TestCase):
    def test_valid_ipv4(self):
        res = TargetResolver.resolve("127.0.0.1")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.ip, "127.0.0.1")

    def test_strip_protocol_and_slashes(self):
        res = TargetResolver.resolve("http://127.0.0.1:8080/path")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.ip, "127.0.0.1")

    def test_invalid_target(self):
        res = TargetResolver.resolve("this.domain.does.not.exist.example.invalid")
        self.assertFalse(res.is_valid)
        self.assertIsNotNone(res.error_message)

    def test_empty_target(self):
        res = TargetResolver.resolve("")
        self.assertFalse(res.is_valid)


class TestPortParser(unittest.TestCase):
    def test_single_port(self):
        ports = parse_ports("80")
        self.assertEqual(ports, [80])

    def test_port_list(self):
        ports = parse_ports("22,80,443")
        self.assertEqual(ports, [22, 80, 443])

    def test_port_range(self):
        ports = parse_ports("80-83")
        self.assertEqual(ports, [80, 81, 82, 83])

    def test_mixed_spec(self):
        ports = parse_ports("22,80-82,443")
        self.assertEqual(ports, [22, 80, 81, 82, 443])

    def test_top_ports(self):
        ports = parse_ports(None, top_ports=10)
        self.assertEqual(len(ports), 10)
        self.assertEqual(ports, TOP_100_PORTS[:10])

    def test_default_ports(self):
        ports = parse_ports(None)
        self.assertEqual(ports, TOP_100_PORTS)

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-50")

    def test_out_of_bounds_port(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")


from unittest.mock import MagicMock, patch

class TestSocketProbe(unittest.TestCase):
    @patch("socket.socket")
    def test_probe_open_port_with_banner(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        # connect_ex returns 0 for open
        mock_sock.connect_ex.return_value = 0
        # recv returns banner
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n"

        probe = SocketProbe(timeout=1.0, banner_grab=True)
        res = probe.probe("192.168.1.1", 22)

        self.assertEqual(res.state, "OPEN")
        self.assertTrue(res.is_open)
        self.assertEqual(res.port, 22)
        self.assertEqual(res.service, "SSH (Secure Shell)")
        self.assertIn("SSH-2.0-OpenSSH_8.9p1", res.banner)

    @patch("socket.socket")
    def test_probe_closed_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        # 10061 / 111 is connection refused
        mock_sock.connect_ex.return_value = 10061

        probe = SocketProbe(timeout=1.0, banner_grab=False)
        res = probe.probe("192.168.1.1", 81)

        self.assertEqual(res.state, "CLOSED")
        self.assertFalse(res.is_open)

    @patch("socket.socket")
    def test_probe_filtered_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        # 10060 is timeout
        mock_sock.connect_ex.return_value = 10060

        probe = SocketProbe(timeout=1.0, banner_grab=False)
        res = probe.probe("192.168.1.1", 4444)

        self.assertEqual(res.state, "FILTERED")
        self.assertFalse(res.is_open)


class TestResultAggregator(unittest.TestCase):
    def test_aggregation_and_json(self):
        target = ResolvedTarget(raw_target="127.0.0.1", ip="127.0.0.1", is_valid=True)
        agg = ResultAggregator(target, total_ports=3, no_color=True)
        agg.start()

        r1 = PortResult(port=80, state="OPEN", service="HTTP", banner="Server: Apache", latency_ms=5.2)
        r2 = PortResult(port=443, state="CLOSED", service="HTTPS", latency_ms=1.1)
        r3 = PortResult(port=8080, state="FILTERED", service="HTTP-Alt", latency_ms=500.0)

        agg.add_result(r1, live_notify=False)
        agg.add_result(r2, live_notify=False)
        agg.add_result(r3, live_notify=False)
        agg.finish()

        self.assertEqual(len(agg.open_ports), 1)
        self.assertEqual(len(agg.closed_ports), 1)
        self.assertEqual(len(agg.filtered_ports), 1)

        # Test JSON export
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tf_path = tf.name

        try:
            agg.export_json(tf_path)
            with open(tf_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["target"]["ip"], "127.0.0.1")
            self.assertEqual(data["scan_metadata"]["open_count"], 1)
            self.assertEqual(data["open_ports"][0]["port"], 80)
            self.assertEqual(data["open_ports"][0]["banner"], "Server: Apache")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


class TestThreadPoolEngine(unittest.TestCase):
    def test_scan_engine(self):
        target = ResolvedTarget(raw_target="127.0.0.1", ip="127.0.0.1", is_valid=True)
        agg = ResultAggregator(target, total_ports=4, no_color=True)

        mock_probe = MagicMock()
        def mock_probe_func(ip, port):
            if port == 80:
                return PortResult(port=80, state="OPEN", service="HTTP", latency_ms=2.0)
            return PortResult(port=port, state="CLOSED", service="Unknown", latency_ms=1.0)

        mock_probe.probe.side_effect = mock_probe_func

        ports_to_scan = [80, 81, 82, 83]
        engine = ThreadPoolEngine(
            target_ip="127.0.0.1",
            ports=ports_to_scan,
            probe=mock_probe,
            aggregator=agg,
            num_threads=2,
            show_progress=False
        )
        engine.run()

        open_found = [r.port for r in agg.open_ports]
        self.assertEqual(open_found, [80])
        self.assertEqual(len(agg.closed_ports), 3)


if __name__ == "__main__":
    unittest.main()
