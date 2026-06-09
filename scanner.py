"""
TCP Port Scanner
Supports IPv4, IPv6, CIDR ranges, and hostname resolution.
"""

import socket
import concurrent.futures
import ipaddress
import time

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT",
}

def get_service_info(port):
    return COMMON_SERVICES.get(port, "")

class PortResult:
    def __init__(self, port, state, service="", banner="", latency_ms=0.0):
        self.port = port
        self.state = state      # "open" | "closed" | "filtered"
        self.service = service
        self.banner = banner
        self.latency_ms = latency_ms

class ScanResult:
    def __init__(self, target):
        self.target = target
        self.resolved_ip = ""
        self.address_family = ""  # "IPv4" | "IPv6"
        self.scan_start = time.time()
        self.scan_end = 0.0
        self.ports = []
        self.error = ""

    def open_ports(self):
        return [p for p in self.ports if p.state == "open"]

    def duration(self):
        return round(self.scan_end - self.scan_start, 2)

def grab_banner(sock, port, timeout=3):
    """
    Attempts to grab a service banner. 
    Handles 'Client-First' (HTTP) and 'Server-First' (SSH/FTP/etc) protocols.
    """
    try:
        sock.settimeout(timeout)
        if port in [80, 8080, 443]:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        data = sock.recv(1024)

        if not data:
            return ""
            
        banner = data.decode("utf-8", errors="replace").strip()
        return banner.splitlines()[0][:120]
        
    except Exception as e:
        return f"[Error: {type(e).__name__}]"

def probe_port(ip, port, af, timeout, grab_banners):
    service_info = get_service_info(port)
    start = time.monotonic()
    banner = ""
    try:
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result_code = sock.connect_ex((ip, port))
        latency = (time.monotonic() - start) * 1000

        if result_code == 0:
            state = "open"
            if grab_banners:
                banner = grab_banner(sock, port, timeout=2.0)
                if banner:
                    print(f"DEBUG: Captured {banner} on port {port}")
        else:
            state = "closed"
        
        sock.close() 
        return PortResult(port, state, service_info, banner, round(latency, 2))

    except Exception:
        return PortResult(port, "filtered", service_info)

def parse_port_range(port_spec):
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    invalid = [p for p in ports if not (1 <= p <= 65535)]
    if invalid:
        raise ValueError("Invalid ports: {}".format(invalid))
    return sorted(ports)

def expand_targets(target_spec):
    try:
        network = ipaddress.ip_network(target_spec, strict=False)
        for host in network.hosts():
            yield str(host)
    except ValueError:
        yield target_spec

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None

def detect_address_family(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return (socket.AF_INET6, "IPv6")
    except OSError:
        return (socket.AF_INET, "IPv4")

def is_valid_target(target):
    return bool(target.strip())

def scan(target, ports, timeout=1.0, workers=100, grab_banners=False, only_open=True):
    result = ScanResult(target)

    if not is_valid_target(target):
        result.error = "Invalid target: {}".format(target)
        result.scan_end = time.time()
        return result

    resolved = resolve_target(target)
    if not resolved:
        result.error = "Could not resolve host: {}".format(target)
        result.scan_end = time.time()
        return result

    result.resolved_ip = resolved
    af_const, af_label = detect_address_family(resolved)
    result.address_family = af_label

    port_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(probe_port, resolved, port, af_const, timeout, grab_banners): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            pr = future.result()
            if only_open and pr.state != "open":
                continue
            port_results.append(pr)

    result.ports = sorted(port_results, key=lambda p: p.port)
    result.scan_end = time.time()
    return result