"""
Configuration settings.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

# Paths
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
CACHE_DIR = BASE_DIR / ".cache"

OUTPUT_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)

# Cache
CACHE_TTL_SECONDS = 3600 * 6  # 6 hours default

# Rate Limiting
RATE_LIMIT_DELAY = 1.0        # Seconds between requests per collector
MAX_CONCURRENT_COLLECTORS = 8
REQUEST_TIMEOUT = 30           # Seconds per HTTP request
MAX_RETRIES = 3

# API Keys
OTX_API_KEY         = os.getenv("OTX_API_KEY", "")
URLSCAN_API_KEY     = os.getenv("URLSCAN_API_KEY", "")
GITHUB_TOKEN        = os.getenv("GITHUB_TOKEN", "")
CENSYS_API_ID       = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET   = os.getenv("CENSYS_API_SECRET", "")
SHODAN_API_KEY      = os.getenv("SHODAN_API_KEY", "")
SECURITYTRAILS_KEY  = os.getenv("SECURITYTRAILS_KEY", "")
BINARYEDGE_KEY      = os.getenv("BINARYEDGE_KEY", "")

# HTTP Headers
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "application/json",
}

# Graph Settings
GRAPH_PHYSICS_ENABLED = True
GRAPH_HEIGHT = "750px"
GRAPH_WIDTH  = "100%"

# Node color palette per type
NODE_COLORS = {
    "domain":    "#FF6B6B",   # Coral red — root domain
    "subdomain": "#4ECDC4",   # Teal — discovered subdomains
    "ip":        "#FFE66D",   # Yellow — IP addresses
    "url":       "#A8E6CF",   # Mint green — URLs
    "email":     "#C3A6FF",   # Lavender — email addresses
    "cert":      "#FF8B94",   # Salmon — certificates
    "unknown":   "#95A5A6",   # Grey — unknown types
}

NODE_SIZES = {
    "domain":    40,
    "subdomain": 20,
    "ip":        25,
    "url":       15,
    "email":     18,
    "cert":      15,
    "unknown":   12,
}

NODE_SHAPES = {
    "domain":    "star",
    "subdomain": "dot",
    "ip":        "diamond",
    "url":       "square",
    "email":     "triangle",
    "cert":      "triangleDown",
    "unknown":   "ellipse",
}
