<div align="center">

# 🕸️ Mouad-Subdomain finder passive

**A professional passive subdomain intelligence platform**

*Discover, correlate, and visualize the attack surface of any domain — without brute force*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Passive Only](https://img.shields.io/badge/Mode-Passive%20Only-orange?style=flat-square)](README.md)

</div>

---

## Overview

Mouad-Subdomain finder passive is a modular, async Python tool that builds a **graph-based intelligence map** of a target domain by aggregating data from 8 independent passive sources. It produces an **interactive HTML dashboard** with a physics-based relationship graph, filterable data tables, and a full JSON data export — all without active scanning or brute force.

```
INPUT domain
    │
    ├── crt.sh CT logs
    ├── Wayback CDX (URL aggregation)
    ├── CIRCL Passive DNS
    ├── CertSpotter CT logs
    ├── HackerTarget DNS
    ├── AlienVault OTX
    ├── urlscan.io
    └── GitHub code search
         │
    [Normalizer] → typed Nodes
    [Correlator] → dedup + edges
    [Graph Engine] → NetworkX DiGraph
    [Pyvis] → interactive HTML graph
    [Jinja2] → HTML dashboard report
```

---

## Quick Start

```bash
# 1. Clone & enter directory
git clone <repo> && cd "graph subdomains"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run a scan
python main.py tesla.com

# 4. Open report
# output/tesla.com_20260428_201807/report.html
```

---

## Output Structure

Each scan creates a **timestamped folder** inside `output/`:

```
output/
└── tesla.com_20260428_201807/
    ├── report.html      ← Interactive HTML dashboard
    ├── graph.html       ← Standalone Pyvis mind-map
    ├── graph.json       ← D3.js-compatible graph export
    └── data.json        ← Full normalized data export
```

---

## CLI Reference

```
python main.py <domain> [options]
```

| Flag | Description |
|------|-------------|
| `--collectors <names>` | Run specific collectors only |
| `--no-resolve` | Skip subdomain IP resolution (faster) |
| `--no-cache` | Bypass cache, always fetch fresh data |
| `--output <path>` | Custom output directory |
| `--verbose` | Enable debug logging |
| `--list-collectors` | Print all available collectors |
| `--clear-cache` | Wipe the response cache |

**Examples:**
```bash
python main.py github.com
python main.py example.com --collectors crtsh gau otx --no-resolve
python main.py target.com --no-cache --verbose
python main.py --list-collectors
python main.py --clear-cache
```

---

## Collectors

| ID | Source | Finds | API Key |
|----|--------|-------|---------|
| `crtsh` | crt.sh Certificate Transparency | Subdomains, certs | ❌ None |
| `gau` | Wayback Machine CDX API | Subdomains, URLs | ❌ None |
| `passive_dns` | CIRCL Passive DNS | Subdomains, IPs | ❌ None |
| `certspotter` | CertSpotter CT logs | Subdomains, certs | ❌ None |
| `hackertarget` | HackerTarget DNS search | Subdomains, IPs | ❌ None |
| `otx` | AlienVault OTX | Subdomains, IPs | Optional |
| `urlscan` | urlscan.io scans | Subdomains, URLs | Optional |
| `github` | GitHub code search | Code leaks, URLs | Optional |

---

## API Keys (Optional)

Create a `.env` file in the project root to unlock higher rate limits and additional collectors:

```env
# AlienVault OTX — https://otx.alienvault.com
OTX_API_KEY=your_key_here

# urlscan.io — https://urlscan.io
URLSCAN_API_KEY=your_key_here

# GitHub — https://github.com/settings/tokens
GITHUB_TOKEN=your_token_here
```

All collectors work without keys (free tier / public endpoints).

---

## Data Model

**Node types:** `domain` · `subdomain` · `ip` · `url` · `email` · `cert`

**Edge types:**

| Relationship | Direction |
|-------------|-----------|
| `HAS_SUBDOMAIN` | domain → subdomain |
| `RESOLVES_TO` | subdomain → ip |
| `BELONGS_TO` | url → subdomain |
| `HAS_EMAIL` | domain → email |
| `COVERS` | cert → subdomain |

---

## Adding a Custom Collector

```python
# collectors/my_source.py
from collectors.base import BaseCollector

class MyCollector(BaseCollector):
    name = "my-source"
    description = "My custom passive OSINT source"

    async def run(self, target: str) -> list[dict]:
        data = await self._get_json(f"https://api.example.com/{target}")
        return [
            self.make_finding("subdomain", item["host"], self.name)
            for item in (data or [])
        ]
```

Then register it in:
- `collectors/__init__.py` — add import + `__all__` entry
- `main.py` — add to `COLLECTOR_MAP`

---

## Project Structure

```
graph subdomains/
├── main.py                    # CLI entry point
├── config.py                  # Settings, API keys, graph styling
├── requirements.txt
│
├── collectors/                # Passive data collectors
│   ├── base.py                # Abstract base with HTTP helpers
│   ├── crtsh.py
│   ├── gau.py
│   ├── passive_dns.py
│   ├── certspotter.py
│   ├── hackertarget.py
│   ├── otx.py
│   ├── urlscan.py
│   └── github_search.py
│
├── core/
│   ├── pipeline.py            # Async orchestrator
│   ├── normalizer.py          # Raw → typed Node objects
│   ├── correlator.py          # Dedup + IP resolution + edges
│   └── cache.py               # 6h disk-backed cache
│
├── graph/
│   ├── builder.py             # NetworkX DiGraph
│   └── exporter.py            # Pyvis HTML + JSON export
│
├── report/
│   ├── generator.py           # Jinja2 report generator
│   └── templates/report.html  # Dashboard template
│
└── output/                    # Auto-created scan results
    └── {domain}_{timestamp}/
        ├── report.html
        ├── graph.html
        ├── graph.json
        └── data.json
```

---

## Legal Notice

This tool performs **passive OSINT only**. All data is sourced from public APIs and historical databases. No active probing, port scanning, or brute-force techniques are used.

Use responsibly. Only scan domains you own or have explicit written permission to research.

---

<div align="center">
<sub>Built for security researchers · Passive intelligence only · No active scanning</sub>
</div>
