"""
output.py — Simple, clean terminal output.
"""

import json
import csv
import io
from scanner import ScanResult, PortResult
from utils import format_duration

BANNER = r"""
  _____  ___  ____    ____   ___  ____ _____  ____  ____  _   _ _   _ _____  ____
 |_   _|/ __|  _ \  |  _ \ / _ \ | _ \_   _| / ___| / ___|| | | | \ | | ____||  _ \
   | | | |   | |_) | | |_) | | | || |_) || |   \___ \| |    | |_| |  \| |  _|  | |_) |
   | | | |___|  __/  |  __/| |_| ||  _ < | |    ___) | |___ |  _  | |\  | |___ |  _ <
   |_|  \____|_|     |_|    \___/ |_| \_\|_|   |____/ \____||_| |_|_| \_|_____||_| \_\
"""

def print_banner():
    print(BANNER)
    print("  TCP Port Scanner · IPv4 & IPv6 · Service Detection · Banner Grabbing\n")

def print_scan_header(result, port_count):
    w = 62
    print("-" * w)
    print(f"  Target       : {result.target}")
    if result.resolved_ip != result.target:
        print(f"  Resolved IP  : {result.resolved_ip}")
    print(f"  Address Fam  : {result.address_family}")
    print(f"  Ports probed : {port_count}")
    print("-" * w)
    print()

def print_scan_footer(result):
    w = 72
    open_count = len(result.open_ports())
    print("-" * w)
    print(f"  Open ports   : {open_count}")
    print(f"  Scan time    : {format_duration(result.duration())}")
    print("-" * w)
    print()

def print_error(msg):
    print(f"\n  [ERROR] {msg}\n")

def print_warning(msg):
    print(f"\n  [WARN]  {msg}\n")

def print_info(msg):
    print(f"  [*] {msg}")

def print_port_table(result, show_closed=False):
    ports_to_show = result.ports if show_closed else result.open_ports()

    if not ports_to_show:
        print("\n  [!] No open ports found.\n")
        return

    print(f"\n{'PORT':<10} {'STATE':<12} {'SERVICE':<20} {'LATENCY':<15} {'BANNER'}")
    print("=" * 85)

    for p in ports_to_show:
        latency = f"{p.latency_ms:.1f}ms" if p.latency_ms is not None else "—"
        
        display_banner = p.banner if p.banner else "—"
        if len(display_banner) > 40:
            display_banner = display_banner[:37] + "..."
        
        print(f"{p.port:<10} {p.state.upper():<12} {p.service:<20} {latency:<15} {display_banner}")
        print("-" * 85) 
    print()

def to_json(result):
    """Serialize a ScanResult to a pretty-printed JSON string."""
    data = {
        "target": result.target,
        "resolved_ip": result.resolved_ip,
        "address_family": result.address_family,
        "scan_duration_s": result.duration(),
        "open_port_count": len(result.open_ports()),
        "ports": [
            {
                "port": p.port,
                "state": p.state,
                "service": p.service,
                "latency_ms": p.latency_ms,
                "banner": p.banner,
            }
            for p in result.open_ports()
        ],
        "error": result.error,
    }
    return json.dumps(data, indent=2)

def to_csv(result):
    """Serialize open ports of a ScanResult to CSV string."""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["target", "resolved_ip", "address_family", "port", "state", "service", "latency_ms", "banner"],
    )
    writer.writeheader()
    for p in result.open_ports(): 
        writer.writerow({
            "target": result.target,
            "resolved_ip": result.resolved_ip,
            "address_family": result.address_family,
            "port": p.port,
            "state": p.state,
            "service": p.service,
            "latency_ms": p.latency_ms,
            "banner": p.banner,
        })
    return buf.getvalue()