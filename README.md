<div align="center">

# 🛡️ TCP Oracle Scanner

### *A fast, lightweight TCP port scanner — where network probing meets precision insight*

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square\&logo=python\&logoColor=white)
![Async](https://img.shields.io/badge/Threaded%20Engine-4CAF50?style=flat-square)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-9C27B0?style=flat-square)
![IPv6 Ready](https://img.shields.io/badge/IPv6-Supported-2196F3?style=flat-square)

*A pure Python reconnaissance engine capable of revealing open gateways across IPv4, IPv6, and entire CIDR realms.*

</div>

---

## ✨ Core Capabilities

|     | Feature                           | Description                                                                                |
| --- | --------------------------------- | ------------------------------------------------------------------------------------------ |
| 🌐  | **Dual-Stack Awareness**          | Automatically detects and supports both IPv4 and IPv6 targets with correct socket handling |
| 🧭  | **Service Identification Engine** | Maps ports to known services using `services` + enhanced internal fallback registry   |
| 🧪  | **Banner Extraction Module**      | Optional handshake probing to extract service banners from open ports                      |
| 📦  | **Port Profile System**           | Predefined scan sets: `top20`, `top100`, `web`, `db`, `remote`, `mail`, `full`             |
| 🛰️ | **CIDR Sweep Engine**             | Scan entire subnets using CIDR notation like `192.168.1.0/24`                              |
| 💾  | **Multi-Format Exporter**         | Output results as JSON, CSV, or plain text                                                 |
| ⚡   | **Concurrent Scan Core**          | Thread pool engine (default: 100 workers) for high-speed scanning                          |
| 🧩  | **Zero External Dependencies**    | Fully standard-library based — portable and minimal                                        |

---

## 📂 Arcane Structure

```
tcp-port-scanner/
│
├── 🧠 main.py        # CLI invocation layer — argument parsing & orchestration core
├── ⚙️ scanner.py     # Core scanning engine — threading & socket probing logic
├── 📡 services.py    # Port → service name resolution registry
├── 🔧 utils.py       # DNS resolution, validation, and address-family detection
├── 📤 output.py      # Terminal rendering + JSON/CSV export system
└── 🧪 tests.py       # Unit validation suite (stdlib unittest)
```

---

## 🚀 Ritual of Installation

### I — Clone the Repository

```bash
git clone https://github.com/MhamdiJasser/TCP-Port-Scanner.git
cd tcp-port-scanner
```

No dependencies. No setup rituals. Pure execution.

---

## ⚔️ Invocation Syntax

```bash
python main.py TARGET [TARGET ...] [OPTIONS]
```

---

## 🧭 Example Scans

### Basic reconnaissance

```bash
python main.py scanme.nmap.org
```

### Targeted port sweep

```bash
python main.py 192.168.1.1 -p 1-1024
```

### IPv6 probe

```bash
python main.py ::1 -p 22,80,443
```

### Banner extraction enabled

```bash
python main.py example.com --banners
```

### Profile-based scan

```bash
python main.py 10.0.0.1 --profile web
```

### Full subnet sweep

```bash
python main.py 192.168.1.0/24 -p 22,80,443,8080
```

### Exported intelligence report

```bash
python main.py example.com -p 1-1024 -o results.json --format json
```

### High-speed deep scan

```bash
python main.py 10.0.0.1 -p 1-65535 -w 256 -t 0.3
```

---

## ⚙️ Configuration Flags

| Flag            | Meaning                                          |
| --------------- | ------------------------------------------------ |
| `-p, --ports`   | Port specification (`80`, `1-1024`, `22,80,443`) |
| `--profile`     | Predefined scan sets (`web`, `db`, `mail`, etc.) |
| `-t, --timeout` | Connection timeout per port (default: 1.0s)      |
| `-w, --workers` | Thread pool size (default: 100)                  |
| `--banners`     | Enable service banner extraction                 |
| `--show-closed` | Display closed/filtered ports                    |
| `-o, --output`  | Output file path                                 |
| `--format`      | Export format: `json`, `csv`, `txt`              |
| `--no-banner`   | Disable ASCII banner display                     |

---

## 📦 Port Profile Codex

| Profile  | Purpose                                                  |
| -------- | -------------------------------------------------------- |
| `top20`  | Most frequently scanned ports                            |
| `top100` | Default balanced reconnaissance set                      |
| `web`    | HTTP/HTTPS ecosystem (80, 443, 8080, 8443, etc.)         |
| `db`     | Database layer (MySQL, PostgreSQL, Redis, MongoDB, etc.) |
| `remote` | Remote access services (SSH, RDP, VNC, Telnet)           |
| `mail`   | SMTP / IMAP / POP3 infrastructure                        |
| `full`   | Entire 1–65535 port spectrum (slow, exhaustive scan)     |

---

## 📤 Output Formats

### 🧾 JSON Oracle Output

```json
{
  "target": "scanme.nmap.org",
  "resolved_ip": "45.33.32.156",
  "address_family": "IPv4",
  "scan_duration_s": 3.21,
  "open_port_count": 3,
  "ports": [
    {
      "port": 22,
      "state": "open",
      "service": "SSH",
      "latency_ms": 142.3,
      "banner": "SSH-2.0-OpenSSH_6.6.1p1"
    }
  ],
  "error": ""
}
```

### 📊 CSV Stream

```csv
target,resolved_ip,address_family,port,state,service,latency_ms,banner
scanme.nmap.org,45.33.32.156,IPv4,22,open,SSH,142.3,SSH-2.0-OpenSSH_6.6.1p1
```

---

## 🧪 Testing the Engine

```bash
python -m pytest tests.py -v
```

or fallback:

```bash
python tests.py
```
