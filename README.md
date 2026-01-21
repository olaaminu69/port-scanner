# Enhanced Port Scanner

A professional-grade, multi-threaded TCP port scanner built in Python with service detection, banner grabbing, and multiple export formats.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- ✅ **Multi-threaded scanning** - Fast parallel port checking
- ✅ **Service detection** - Identifies common services on open ports
- ✅ **Banner grabbing** - Attempts to retrieve service banners
- ✅ **Progress tracking** - Real-time progress bar with color-coded output
- ✅ **Multiple export formats** - JSON, CSV, and TXT reports
- ✅ **Flexible port ranges** - Common ports, custom ranges, or full scan
- ✅ **CLI support** - Full command-line interface with arguments
- ✅ **Hostname resolution** - Supports both IP addresses and hostnames

## Installation

### Prerequisites
- Python 3.7 or higher

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/port-scanner.git
cd port-scanner
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Interactive Mode
```bash
python scanner.py
```

### Command Line Mode

**Scan common ports:**
```bash
python scanner.py -t 192.168.1.1 -p common
```

**Scan specific range:**
```bash
python scanner.py -t scanme.nmap.org -p 1-1000
```

**Scan all ports (1-65535):**
```bash
python scanner.py -t 10.0.0.1 -p all
```

**Export results to JSON:**
```bash
python scanner.py -t example.com -p common -o json
```

**Use custom thread count:**
```bash
python scanner.py -t 192.168.1.1 -p 1-100 --threads 200
```

### Command Line Arguments
```
-t, --target      Target IP address or hostname (required)
-p, --ports       Port range: common, all, or custom (e.g., 80-443)
-o, --output      Export format: json, csv, or txt
--threads         Number of scanning threads (default: 100)
-v, --verbose     Enable verbose output
-h, --help        Show help message
```

## Screenshots
### Scan Help
![Scan Help](Screenshot\From\2026-01-21\07-17-25.png)

### Scan in Progress
![Scan Progress](Screenshot\From\2026-01-21\08-09-54.png)

### Results Output
![Results](Screenshot\From\2026-01-21\08-10-07.png)

### JSON Export
![JSON Export](Screenshot\From\2026-01-21\08-11-47.png)
```
