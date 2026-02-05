#!/usr/bin/env python3

import warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

from concurrent.futures import ThreadPoolExecutor, as_completed
from Wappalyzer import Wappalyzer, WebPage
import requests
import urllib3
import argparse
import socket
import json
import csv
import sys
import os
import time
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Colors ---
GREEN = "\033[38;5;120m"
BLUE = "\033[38;5;81m"
PURPLE = "\033[38;5;99m"
YELLOW = "\033[38;5;228m"
BOLD = "\033[1m"
DIM = "\033[2m"
END = "\033[0m"

BANNER = f"""{BLUE}
                 _
  __ _ _ __ _ __| |_  _ ______ _ _
 / _` | '_ \\ '_ \\ | || |_ / -_) '_|
 \\__,_| .__/ .__/_|\\_, /__\\___|_|
      |_|  |_|     |__/   @gkdata
{END}"""

# User-Agent strings to rotate through for WAF evasion
USER_AGENTS = [
    # Googlebot
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/131.0.6778.135 Safari/537.36",
    # Bingbot
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    # Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
]

# Thread-safe counter for progress
_lock = threading.Lock()
_progress = {"done": 0, "total": 0}


def dns_resolve(hostname):
    """Quick DNS check. Returns True if hostname resolves."""
    try:
        socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        return False


def classify_error(e):
    """Extract a short, readable error message from an exception."""
    msg = str(e)
    if "NameResolutionError" in msg or "getaddrinfo failed" in msg or "Name or service not known" in msg:
        return "DNS resolution failed"
    if "ConnectTimeoutError" in msg or "timed out" in msg.lower():
        return "Connection timed out"
    if "ConnectionRefusedError" in msg or "Connection refused" in msg:
        return "Connection refused"
    if "SSLError" in msg or "SSL" in msg:
        return "SSL/TLS error"
    if "TooManyRedirects" in msg:
        return "Too many redirects"
    if "ConnectionResetError" in msg or "Connection reset" in msg:
        return "Connection reset by host"
    if "Max retries exceeded" in msg:
        # Strip the verbose wrapper, keep inner cause
        if "Caused by" in msg:
            inner = msg.split("Caused by ")[-1].rstrip(")")
            return classify_error(Exception(inner))
        return "Max retries exceeded"
    # Fallback: truncate long messages
    if len(msg) > 80:
        return msg[:77] + "..."
    return msg


def _make_request(url, headers, timeout, verify_ssl):
    """Make a single HTTP request and return a WebPage."""
    response = requests.get(
        url, headers=headers, timeout=timeout,
        verify=verify_ssl, allow_redirects=True
    )
    return WebPage(response.url, html=response.text, headers=response.headers)


def fetch_webpage(url, ua, timeout=10, verify_ssl=False, retries=2):
    """Fetch a webpage with custom User-Agent, retry logic, and HTTP fallback."""
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    # Quick DNS pre-check to skip retries on dead hosts
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]
    if not dns_resolve(hostname):
        raise ConnectionError("DNS resolution failed")

    last_err = None
    for attempt in range(retries + 1):
        try:
            return _make_request(url, headers, timeout, verify_ssl)
        except requests.exceptions.SSLError:
            # HTTPS failed with SSL error — try HTTP fallback
            if url.startswith("https://"):
                http_url = "http://" + url[8:]
                try:
                    return _make_request(http_url, headers, timeout, verify_ssl)
                except Exception:
                    pass
            last_err = ConnectionError("SSL/TLS error (HTTP fallback also failed)")
            break
        except requests.exceptions.ConnectionError as e:
            # If it's a non-DNS connection error, try HTTP fallback on last attempt
            if attempt == retries and url.startswith("https://"):
                http_url = "http://" + url[8:]
                try:
                    return _make_request(http_url, headers, timeout, verify_ssl)
                except Exception:
                    pass
            last_err = e
            if attempt < retries:
                time.sleep(1 * (attempt + 1))
        except requests.exceptions.Timeout as e:
            last_err = e
            if attempt < retries:
                time.sleep(1 * (attempt + 1))
        except Exception as e:
            raise e

    raise last_err


def get_ua(index, mode="googlebot"):
    """Get a User-Agent string based on mode."""
    if mode == "googlebot":
        return USER_AGENTS[index % 2]  # Rotate between Googlebot UAs
    elif mode == "bingbot":
        return USER_AGENTS[2]
    elif mode == "chrome":
        return USER_AGENTS[3]
    elif mode == "firefox":
        return USER_AGENTS[4]
    elif mode == "rotate":
        return USER_AGENTS[index % len(USER_AGENTS)]
    else:
        return USER_AGENTS[0]


def format_tech_plain(url, tech_dict):
    """Format technology results as a plain text line."""
    parts = []
    for name, info in sorted(tech_dict.items()):
        versions = info.get("versions", [])
        if versions:
            parts.append(f"{name} ({', '.join(versions)})")
        else:
            parts.append(name)
    return f"{url} | {' - '.join(parts)}" if parts else f"{url} | No technologies detected"


def format_tech_console(url, tech_dict):
    """Format technology results for colorized console output."""
    parts = []
    for name, info in sorted(tech_dict.items()):
        categories = info.get("categories", [])
        versions = info.get("versions", [])
        cat_str = f"{DIM}[{', '.join(categories)}]{END}" if categories else ""
        ver_str = f" {YELLOW}{', '.join(versions)}{END}" if versions else ""
        parts.append(f"{BLUE}{BOLD}{name}{END}{ver_str} {cat_str}")
    return parts


def check(wappalyzer, url, ua, timeout, verify_ssl, retries):
    """Analyze a single URL and return results."""
    if not url.startswith("http"):
        url = "https://" + url

    webpage = fetch_webpage(url, ua, timeout=timeout, verify_ssl=verify_ssl, retries=retries)
    tech = wappalyzer.analyze_with_versions_and_categories(webpage)

    with _lock:
        _progress["done"] += 1
        count = _progress["done"]
        total = _progress["total"]

    tech_parts = format_tech_console(url, tech)
    if tech_parts:
        tech_line = ", ".join(tech_parts)
    else:
        tech_line = f"{DIM}No technologies detected{END}"

    print(f"  {GREEN}[{count}/{total}]{END} {BOLD}{url}{END}")
    print(f"         {tech_line}")

    return {"url": url, "technologies": tech}


def write_results(results, output_path, fmt):
    """Write results to a file in the specified format."""
    if fmt == "json":
        # Build clean JSON structure
        data = []
        for r in results:
            entry = {"url": r["url"], "technologies": []}
            for name, info in sorted(r["technologies"].items()):
                entry["technologies"].append({
                    "name": name,
                    "versions": info.get("versions", []),
                    "categories": info.get("categories", []),
                })
            data.append(entry)
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

    elif fmt == "csv":
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Technology", "Version", "Categories"])
            for r in results:
                if not r["technologies"]:
                    writer.writerow([r["url"], "", "", ""])
                for name, info in sorted(r["technologies"].items()):
                    writer.writerow([
                        r["url"],
                        name,
                        "; ".join(info.get("versions", [])),
                        "; ".join(info.get("categories", [])),
                    ])

    else:  # txt (default)
        with open(output_path, "w") as f:
            for r in results:
                f.write(format_tech_plain(r["url"], r["technologies"]) + "\n")


def print_summary(results, errors):
    """Print a summary of all detected technologies and errors."""
    total_scanned = len(results) + len(errors)
    all_tech = {}
    for r in results:
        for name, info in r["technologies"].items():
            if name not in all_tech:
                all_tech[name] = {"count": 0, "categories": info.get("categories", [])}
            all_tech[name]["count"] += 1

    print(f"\n{PURPLE}{'─' * 50}{END}")
    print(f"{PURPLE}{BOLD} Summary{END}")
    print(f"{PURPLE}{'─' * 50}{END}")
    print(f"  Targets:      {BOLD}{total_scanned}{END}")
    print(f"  Successful:   {GREEN}{BOLD}{len(results)}{END}")
    print(f"  Failed:       {PURPLE}{BOLD}{len(errors)}{END}")
    if all_tech:
        print(f"  Technologies: {BOLD}{len(all_tech)}{END} unique")

    # Error breakdown
    if errors:
        err_types = {}
        for e in errors:
            reason = e["error"]
            err_types[reason] = err_types.get(reason, 0) + 1
        print(f"\n  {BOLD}Errors:{END}")
        for reason, count in sorted(err_types.items(), key=lambda x: x[1], reverse=True):
            print(f"    {PURPLE}{count:>4}x{END} {reason}")

    # Top technologies by frequency
    if all_tech:
        sorted_tech = sorted(all_tech.items(), key=lambda x: x[1]["count"], reverse=True)
        top = sorted_tech[:10]
        print(f"\n  {BOLD}Most common:{END}")
        for name, info in top:
            cats = f" {DIM}({', '.join(info['categories'])}){END}" if info["categories"] else ""
            bar = "█" * min(info["count"], 30)
            print(f"    {GREEN}{bar}{END} {name}{cats} ({info['count']})")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Web technology detection tool powered by Wappalyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain", help="Single domain to analyze", type=str)
    parser.add_argument("-f", "--file", help="File containing list of domains (one per line)", type=str)
    parser.add_argument("-t", "--threads", help="Number of concurrent threads (default: 5)", type=int, default=5)
    parser.add_argument("-o", "--output", help="Save results to file", type=str)
    parser.add_argument("-F", "--format", help="Output format: txt, json, csv (default: txt)",
                        choices=["txt", "json", "csv"], default="txt")
    parser.add_argument("-T", "--timeout", help="Request timeout in seconds (default: 10)", type=int, default=10)
    parser.add_argument("-r", "--retries", help="Number of retries per domain (default: 2)", type=int, default=2)
    parser.add_argument("-i", "--ignore", help="Suppress error messages", action="store_true")
    parser.add_argument("--ua", help="User-Agent mode: googlebot, bingbot, chrome, firefox, rotate (default: googlebot)",
                        default="googlebot", choices=["googlebot", "bingbot", "chrome", "firefox", "rotate"])
    parser.add_argument("--verify-ssl", help="Verify SSL certificates", action="store_true")

    args = parser.parse_args()

    # Load domains
    domains = []
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{PURPLE}Error:{END} File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r") as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif args.domain:
        domains.append(args.domain)
    else:
        parser.print_help()
        sys.exit(1)

    if not domains:
        print(f"{PURPLE}Error:{END} No domains to analyze.")
        sys.exit(1)

    # Show config
    print(f"  {GREEN}Targets:{END}    {BOLD}{len(domains)}{END} domain(s)")
    print(f"  {GREEN}Threads:{END}    {BOLD}{args.threads}{END}")
    print(f"  {GREEN}User-Agent:{END} {BOLD}{args.ua}{END}")
    print(f"  {GREEN}Timeout:{END}    {BOLD}{args.timeout}s{END}")
    if args.output:
        print(f"  {GREEN}Output:{END}     {BOLD}{args.output}{END} ({args.format})")
    print()

    # Initialize Wappalyzer
    wappalyzer = Wappalyzer.latest()

    # Set up progress tracking
    _progress["total"] = len(domains)
    _progress["done"] = 0

    results = []
    errors = []

    print(f"{PURPLE}{BOLD} Scanning...{END}\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_domain = {}
        for i, domain in enumerate(domains):
            ua = get_ua(i, args.ua)
            future = executor.submit(
                check, wappalyzer, domain, ua, args.timeout, args.verify_ssl, args.retries
            )
            future_to_domain[future] = domain

        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                with _lock:
                    _progress["done"] += 1
                    count = _progress["done"]
                    total = _progress["total"]
                short_err = classify_error(e)
                errors.append({"domain": domain, "error": short_err})
                if not args.ignore:
                    print(f"  {PURPLE}[{count}/{total}] Error:{END} {BOLD}{domain}{END} > {DIM}{short_err}{END}")

    # Write output file
    if args.output and results:
        write_results(results, args.output, args.format)
        print(f"\n  {GREEN}Results saved to:{END} {BOLD}{args.output}{END}")

    # Print summary
    print_summary(results, errors)


if __name__ == "__main__":
    main()
