"""
tests.py — Unit tests for tcp-port-scanner.

Run with:  python -m unittest tests.py -v or:  python tests.py

"""

import sys
import unittest
from unittest.mock import patch, MagicMock
import socket
import os

sys.path.insert(0, os.path.dirname(__file__))

from utils import resolve_target, detect_address_family, is_valid_target, format_duration
from services import get_service_info
from scanner import parse_port_range, ScanResult, PortResult, probe_port

class TestIsValidTarget(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(is_valid_target("192.168.1.1"))

    def test_valid_ipv6(self):
        self.assertTrue(is_valid_target("::1"))
        self.assertTrue(is_valid_target("2001:db8::1"))

    def test_valid_hostname(self):
        self.assertTrue(is_valid_target("example.com"))
        self.assertTrue(is_valid_target("sub.domain.co.uk"))

    def test_valid_cidr(self):
        self.assertTrue(is_valid_target("10.0.0.0/8"))

    def test_invalid_empty(self):
        self.assertFalse(is_valid_target(""))

    def test_invalid_chars(self):
        self.assertFalse(is_valid_target("not a host!"))


class TestDetectAddressFamily(unittest.TestCase):
    def test_ipv4(self):
        af, label = detect_address_family("192.168.1.1")
        self.assertEqual(af, socket.AF_INET)
        self.assertEqual(label, "IPv4")

    def test_ipv6(self):
        af, label = detect_address_family("::1")
        self.assertEqual(af, socket.AF_INET6)
        self.assertEqual(label, "IPv6")

    def test_ipv6_full(self):
        af, label = detect_address_family("2001:db8::ff00:42:8329")
        self.assertEqual(af, socket.AF_INET6)
        self.assertEqual(label, "IPv6")


class TestFormatDuration(unittest.TestCase):
    def test_sub_minute(self):
        self.assertEqual(format_duration(0.42), "0.42s")
        self.assertEqual(format_duration(59.99), "59.99s")

    def test_over_minute(self):
        result = format_duration(125.5)
        self.assertIn("2m", result)


class TestResolveTarget(unittest.TestCase):
    def test_loopback_ipv4(self):
        ip = resolve_target("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")

    def test_loopback_ipv6(self):
        ip = resolve_target("::1")
        self.assertIsNotNone(ip)

    def test_invalid_host(self):
        ip = resolve_target("this.host.does.not.exist.invalid")
        self.assertIsNone(ip)

class TestGetServiceInfo(unittest.TestCase):
    def test_http(self):
        name = get_service_info(80)
        self.assertIn("http", name.lower())

    def test_ssh(self):
        name = get_service_info(22)
        self.assertIn("ssh", name.lower())

    def test_unknown_port(self):
        name = get_service_info(59999)
        self.assertIsInstance(name, str)

    def test_common_db_ports(self):
        self.assertIn("mysql", get_service_info(3306).lower())
        self.assertIn("postgres", get_service_info(5432).lower())
        self.assertIn("redis", get_service_info(6379).lower())

class TestParsePortRange(unittest.TestCase):
    def test_single(self):
        self.assertEqual(parse_port_range("80"), [80])

    def test_range(self):
        self.assertEqual(parse_port_range("1-5"), [1, 2, 3, 4, 5])

    def test_list(self):
        self.assertEqual(parse_port_range("22,80,443"), [22, 80, 443])

    def test_mixed(self):
        result = parse_port_range("22,80-82,443")
        self.assertEqual(result, [22, 80, 81, 82, 443])

    def test_sorted(self):
        result = parse_port_range("443,80,22")
        self.assertEqual(result, [22, 80, 443])

    def test_invalid_zero(self):
        with self.assertRaises(ValueError):
            parse_port_range("0")

    def test_invalid_too_large(self):
        with self.assertRaises(ValueError):
            parse_port_range("65536")


class TestProbePort(unittest.TestCase):
    """Mock-based tests for probe_port."""

    @patch("scanner.socket.socket")
    def test_open_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        result = probe_port("127.0.0.1", 80, socket.AF_INET, 1.0, False)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.port, 80)

    @patch("scanner.socket.socket")
    def test_closed_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111
        mock_socket_cls.return_value = mock_sock

        result = probe_port("127.0.0.1", 9999, socket.AF_INET, 1.0, False)
        self.assertEqual(result.state, "closed")

    @patch("scanner.socket.socket")
    def test_filtered_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout
        mock_socket_cls.return_value = mock_sock

        result = probe_port("127.0.0.1", 12345, socket.AF_INET, 1.0, False)
        self.assertEqual(result.state, "filtered")


class TestScanResult(unittest.TestCase):
    def make_result(self):
        r = ScanResult("test")
        r.resolved_ip = "127.0.0.1"
        r.address_family = "IPv4"
        r.ports = [
            PortResult(22, "open", "SSH"),
            PortResult(80, "open", "HTTP"),
            PortResult(443, "closed", "HTTPS"),
            PortResult(8080, "filtered", "HTTP Alt"),
        ]
        return r

    def test_open_ports(self):
        r = self.make_result()
        open_ports = r.open_ports()
        self.assertEqual(len(open_ports), 2)
        self.assertTrue(all(p.state == "open" for p in open_ports))

    def test_duration(self):
        import time
        r = ScanResult("t")
        r.scan_start = time.time() - 5
        r.scan_end = time.time()
        self.assertGreater(r.duration(), 4.9)

if __name__ == "__main__":
    unittest.main(verbosity=2)