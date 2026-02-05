

# Applyzer - Web Technology Detection Tool

## Overview

Applyzer leverages the Wappalyzer engine to detect technologies powering websites — CMS platforms, JavaScript frameworks, web servers, analytics tools, and more. It supports batch scanning with multithreading, WAF-friendly User-Agent spoofing, and multiple output formats.

## Features

- **WAF evasion** — Uses Googlebot/Bingbot/browser User-Agent strings to avoid getting blocked
- **Rich detection** — Returns technology names, versions, and categories (not just names)
- **Multiple output formats** — Save results as TXT, JSON, or CSV
- **Batch scanning** — Process thousands of domains from a file with configurable threads
- **Retry logic** — Automatic retries on connection errors and timeouts
- **Progress tracking** — Live `[n/total]` counter during scans
- **Summary report** — Shows unique technology counts and most common technologies after scan

## Installation

```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install python-Wappalyzer requests beautifulsoup4 lxml aiohttp
```

## Usage

```
python applyzer.py -d <domain> [options]
python applyzer.py -f <file>   [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --domain` | Single domain to analyze | — |
| `-f, --file` | File with domains (one per line, `#` comments supported) | — |
| `-t, --threads` | Number of concurrent threads | 5 |
| `-o, --output` | Save results to file | — |
| `-F, --format` | Output format: `txt`, `json`, `csv` | txt |
| `-T, --timeout` | Request timeout in seconds | 10 |
| `-r, --retries` | Retries per domain on failure | 2 |
| `-i, --ignore` | Suppress error messages | off |
| `--ua` | User-Agent mode: `googlebot`, `bingbot`, `chrome`, `firefox`, `rotate` | googlebot |
| `--verify-ssl` | Verify SSL certificates | off |

### Examples

**Single domain:**
```bash
python applyzer.py -d example.com
```

**Batch scan with JSON output:**
```bash
python applyzer.py -f domains.txt -t 10 -o results.json -F json
```

**Rotate User-Agents across requests:**
```bash
python applyzer.py -f targets.txt -t 20 --ua rotate -o scan.csv -F csv
```

**Use Chrome UA with SSL verification:**
```bash
python applyzer.py -d example.com --ua chrome --verify-ssl
```

### Output Formats

**JSON** (`-F json`):
```json
[
  {
    "url": "https://example.com",
    "technologies": [
      {"name": "Nginx", "versions": ["1.19"], "categories": ["Web servers"]},
      {"name": "React", "versions": [], "categories": ["JavaScript frameworks"]}
    ]
  }
]
```

**CSV** (`-F csv`):
```
URL,Technology,Version,Categories
https://example.com,Nginx,1.19,Web servers
https://example.com,React,,JavaScript frameworks
```

**TXT** (`-F txt`, default):
```
https://example.com | Nginx (1.19) - React
```

## Disclaimer

Ensure you have the necessary permissions to analyze target domains. Usage of this tool must comply with all applicable laws and regulations.
