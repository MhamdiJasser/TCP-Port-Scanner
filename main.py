#!/usr/bin/env python3
"""
tcp-port-scanner — CLI entry point.

Usage examples
--------------
# Scan top-1000 ports on a hostname
python main.py scanme.nmap.org

# Custom port range with banner grabbing
python main.py 192.168.1.1 -p 1-1024 --banners

# IPv6 target
python main.py ::1 -p 22,80,443

# CIDR sweep (show only open)
python main.py 192.168.1.0/24 -p 22,80,443,8080

# Export results to JSON
python main.py example.com -p 1-1024 --output results.json --format json

# Increase concurrency, lower timeout
python main.py 10.0.0.1 -p 1-65535 -w 256 -t 0.5

Run `python main.py --help` for the full option list.
"""

import argparse
import sys
import os

from scanner import scan, parse_port_range, expand_targets
from output import (
    print_banner,
    print_scan_header,
    print_scan_footer,
    print_port_table,
    print_error,
    print_info,
    print_warning,
    to_json,
    to_csv,
)

PORT_PROFILES = {
    "top20":  "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
    "top100": (
        "7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,"
        "139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,"
        "548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,"
        "1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,"
        "3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,"
        "5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,"
        "9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"
    ),
    "web":     "80,443,8000,8008,8080,8443,8888,9000,9443",
    "db":      "1433,1521,3306,5432,6379,9042,9200,27017,27018",
    "remote":  "22,23,3389,5900,5901",
    "mail":    "25,110,143,465,587,993,995",
    "full":    "1-65535",
}

def build_parser():
    parser = argparse.ArgumentParser(
        prog="tcp-port-scanner",
        description="TCP Port Scanner — IPv4 & IPv6 · Service Detection · Banner Grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Port profiles (use with --profile):
  top20   — 20 most common ports
  top100  — 100 most common ports  (default)
  web     — HTTP/HTTPS ports
  db      — common database ports
  remote  — SSH, Telnet, RDP, VNC
  mail    — SMTP, POP3, IMAP + TLS variants
  full    — all 65535 ports (slow!)

Examples:
  python main.py scanme.nmap.org
  python main.py 192.168.1.1 -p 1-1024 --banners
  python main.py ::1 -p 22,80,443
  python main.py 10.0.0.0/24 --profile web
  python main.py example.com -p 1-1024 -o results.json --format json
        """,
    )

    parser.add_argument("targets", nargs="+", metavar="TARGET",
                        help="Hostname(s), IPv4/IPv6 address(es), or CIDR block(s)")

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument("-p", "--ports", metavar="PORTS",
                            help="Port spec: '80', '1-1024', '22,80,443'")
    port_group.add_argument("--profile", choices=PORT_PROFILES.keys(), default="top100",
                            help="Named port profile (default: top100)")

    parser.add_argument("-t", "--timeout", type=float, default=1.0, metavar="SEC",
                        help="Per-port connection timeout in seconds (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100, metavar="N",
                        help="Max concurrent threads (default: 100)")
    parser.add_argument("--banners", action="store_true",
                        help="Attempt to grab service banners from open ports")
    parser.add_argument("--show-closed", action="store_true",
                        help="Also display closed/filtered ports in the table")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write results to this file")
    parser.add_argument("--format", choices=["json", "csv", "txt"], default="json",
                        metavar="FMT",
                        help="Output format when --output is used (default: json)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress the ASCII art banner")

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    try:
        ports = parse_port_range(args.ports) if args.ports else parse_port_range(PORT_PROFILES[args.profile])
    except ValueError as exc:
        print_error(str(exc))
        return 1

    print_info(f"Port profile : {args.profile if not args.ports else 'custom'} ({len(ports)} ports)")
    print_info(f"Timeout      : {args.timeout}s per port")
    print_info(f"Workers      : {args.workers} concurrent threads")
    if args.banners:
        print_info("Banner grab  : enabled")
    print()

    all_targets = []
    for raw in args.targets:
        expanded = list(expand_targets(raw))
        all_targets.extend(expanded)

    all_results = []
    for target in all_targets:
        result = scan(
            target=target,
            ports=ports,
            timeout=args.timeout,
            workers=args.workers,
            grab_banners=args.banners,
            only_open=not args.show_closed,
        )

        if result.error:
            print_error(result.error)
            continue

        print_scan_header(result, len(ports))
        print_port_table(result, show_closed=args.show_closed)
        print_scan_footer(result)
        all_results.append(result)

    if args.output and all_results:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                if args.format == "json":
                    combined = [json.loads(to_json(r)) for r in all_results]
                    fh.write(json.dumps(combined, indent=2))
                elif args.format == "csv":
                    fh.write(to_csv(all_results[0]))
                else:
                    fh.write("\n".join([f"Target: {r.target}" for r in all_results]))
            print_info(f"Results saved → {os.path.abspath(args.output)}")
        except OSError as exc:
            print_error(f"Could not write output file: {exc}")

if __name__ == "__main__":
    sys.exit(main())