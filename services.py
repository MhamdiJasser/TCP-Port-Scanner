"""
services.py — Port → service name mapping.

"""

import socket

_WELL_KNOWN = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP Submission",
    631: "IPP (CUPS)",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    2181: "ZooKeeper",
    2375: "Docker (plain)",
    2376: "Docker (TLS)",
    2379: "etcd client",
    2380: "etcd peer",
    3000: "Dev server / Grafana",
    3306: "MySQL",
    3389: "RDP",
    4369: "Erlang EPMD",
    5000: "Dev server / Flask",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "AMQP (RabbitMQ)",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    6881: "BitTorrent",
    7001: "WebLogic",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    8888: "Jupyter Notebook",
    9000: "SonarQube / PHP-FPM",
    9042: "Cassandra",
    9090: "Prometheus",
    9092: "Kafka",
    9200: "Elasticsearch HTTP",
    9300: "Elasticsearch Transport",
    10250: "Kubelet API",
    11211: "Memcached",
    15672: "RabbitMQ Management",
    27017: "MongoDB",
    27018: "MongoDB Shard",
    50000: "SAP / Jenkins",
}

def get_service_info(port):
    """
    Return a human-readable service name for a TCP port.

    Resolution order:
      1. socket.getservbyport()
      2. _WELL_KNOWN dictionary
      3. "unknown"
    """
    try:
        name = socket.getservbyport(port, "tcp")

        if len(name) <= 5:
            return name.upper()

        return name.title()

    except OSError:
        pass

    return _WELL_KNOWN.get(port, "unknown")