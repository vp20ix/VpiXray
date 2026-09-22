#!/usr/bin/env python3
import argparse
import sys
import urllib3

from utils.banner import show_banner
from utils.colors import console
from utils.reporter import print_results, export_json

from core.requester import Requester
from core.headers_check import check_headers
from core.sensitive import check_sensitive
from core.redirect import check_redirect
from core.xss import check_xss
from core.sqli import check_sqli
from core.fingerprint import check_fingerprint
from core.sqli import check_sqli_time
from core.cmdi import check_cmdi
from core.lfi import check_lfi
from core.csrf import check_csrf
from core.idor import check_idor
from core.ssrf import check_ssrf
from core.xxe import check_xxe
from core.ssti import check_ssti
from core.cors import check_cors
from core.hostheader import check_host_header
from core.dirlisting import check_dirlisting
from core.crlf import check_crlf
from core.jwt import check_jwt
from core.sqli_blind import check_sqli_blind
from core.nosqli import check_nosqli
from recon.ipinfo import check_ipinfo
from recon.dns_lookup import check_dns
from recon.whois_lookup import check_whois
from recon.ssl_info import check_ssl
from recon.server_info import check_server_info
from recon.http_methods import check_http_methods
from recon.port_scan import check_port_scan
from recon.subdomain_enum import check_subdomains

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "0.1.0"

RECON_CHECKS = {
    "ipinfo":     ("IP & Geolocation",   check_ipinfo),
    "dns":        ("DNS Records",        check_dns),
    "whois":      ("WHOIS",              check_whois),
    "ssl":        ("SSL/TLS Info",       check_ssl),
    "server":     ("Server Info",        check_server_info),
    "methods":    ("HTTP Methods",       check_http_methods),
    "ports":      ("Port Scan",          check_port_scan),
    "subdomains": ("Subdomain Enum",     check_subdomains),
}

CHECKS = {
    "headers":     ("Security Headers",   check_headers),
    "sensitive":   ("Sensitive Files",    check_sensitive),
    "redirect":    ("Open Redirect",      check_redirect),
    "xss":         ("Reflected XSS",      check_xss),
    "sqli":        ("SQL Injection",      check_sqli),
    "fingerprint": ("Tech Fingerprint",   check_fingerprint),
    "sqli_time":   ("Time-based SQLi",     check_sqli_time),
    "cmdi":        ("Command Injection",   check_cmdi),
    "lfi":         ("LFI",                 check_lfi),
    "csrf":        ("CSRF",                check_csrf),
    "idor":        ("IDOR",                check_idor),
    "ssrf":        ("SSRF",                check_ssrf),
    "xxe":         ("XXE",                 check_xxe),
    "ssti":        ("SSTI",                check_ssti),
    "cors":        ("CORS Misconfig",      check_cors),
    "hostheader":  ("Host Header Inj.",    check_host_header),
    "dirlisting":  ("Directory Listing",   check_dirlisting),
    "crlf":        ("CRLF Injection",      check_crlf),
    "jwt":         ("JWT Analyzer",        check_jwt),
    "sqli_blind":  ("Blind SQLi",          check_sqli_blind),
    "nosqli":      ("NoSQL Injection",     check_nosqli),
}

def parse_args():
    p = argparse.ArgumentParser(
        prog="vpixray",
        description="VpiXray - X-ray for the web. Nothing hides.",
        epilog="Example: vpixray -u https://target.com --all -o report.json",
    )
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument("-v", "--version", action="version", version=f"VpiXray v{__version__}")
    p.add_argument("--all", action="store_true", help="Run all checks")
    p.add_argument("--headers", action="store_true")
    p.add_argument("--sensitive", action="store_true")
    p.add_argument("--redirect", action="store_true")
    p.add_argument("--xss", action="store_true")
    p.add_argument("--sqli", action="store_true")
    p.add_argument("--fingerprint", action="store_true")
    p.add_argument("--sqli-time", action="store_true")
    p.add_argument("--cmdi", action="store_true")
    p.add_argument("--lfi", action="store_true")
    p.add_argument("--csrf", action="store_true")
    p.add_argument("--idor", action="store_true")
    p.add_argument("--ssrf", action="store_true")
    p.add_argument("--xxe", action="store_true")
    p.add_argument("--ssti", action="store_true")
    p.add_argument("--cors", action="store_true")
    p.add_argument("--hostheader", action="store_true")
    p.add_argument("--dirlisting", action="store_true")
    p.add_argument("--crlf", action="store_true")
    p.add_argument("--jwt", action="store_true")
    p.add_argument("--sqli-blind", action="store_true")
    p.add_argument("--nosqli", action="store_true")
    p.add_argument("--recon", action="store_true", help="Full recon (IP+DNS+WHOIS+SSL+Server+Methods+Ports+Subdomains)")
    p.add_argument("--ipinfo", action="store_true", help="IP + Geolocation")
    p.add_argument("--dns", action="store_true", help="DNS records")
    p.add_argument("--whois", action="store_true", help="WHOIS lookup")
    p.add_argument("--ssl-info", action="store_true", help="SSL/TLS info")
    p.add_argument("--server-info", action="store_true", help="Server headers + CDN")
    p.add_argument("--methods", action="store_true", help="HTTP methods")
    p.add_argument("--ports", action="store_true", help="Basic port scan")
    p.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")
    p.add_argument("-w", "--wordlist")
    p.add_argument("-o", "--output")
    p.add_argument("--proxy")
    p.add_argument("--cookie", help="Session cookie")
    p.add_argument("--timeout", type=int, default=10)
    return p.parse_args()

def choose_checks(args):
    if args.all:
        return list(CHECKS.keys())
    return [k for k in CHECKS if getattr(args, k.replace("-", "_"), False)]


def choose_recon(args):
    if args.recon:
        return list(RECON_CHECKS.keys())
    mapping = {
        "ipinfo": "ipinfo", "dns": "dns", "whois": "whois",
        "ssl_info": "ssl", "server_info": "server",
        "methods": "methods", "ports": "ports", "subdomains": "subdomains",
    }
    selected = []
    for arg_name, key in mapping.items():
        if getattr(args, arg_name.replace("-", "_"), False):
            selected.append(key)
    return selected

def main():
    show_banner()
    args = parse_args()
    selected_recon = choose_recon(args)
    selected = choose_checks(args)

    if not selected and not selected_recon:
        console.print("[warn]No checks selected. Use --all, --recon, or specific checks.[/warn]")
        sys.exit(1)
    if not args.url.startswith(("http://", "https://")):
        args.url = "http://" + args.url
    console.print(f"[info]-> Target:[/info] [bold]{args.url}[/bold]")
    if selected_recon:
        console.print(f"[info]-> Recon:[/info] {', '.join(selected_recon)}")
    if selected:
        console.print(f"[info]-> Vuln checks:[/info] {', '.join(selected)}")
    console.print()
    requester = Requester(timeout=args.timeout, proxy=args.proxy, cookie=args.cookie)
    results = []

    # Recon checks first
    for key in selected_recon:
        name, fn = RECON_CHECKS[key]
        console.print(f"\n[title]>> {name}[/title]")
        try:
            r = fn(requester, args.url)
            results.append(r)
        except Exception as e:
            console.print(f"[error]x Error in {name}: {e}[/error]")
            results.append({"name": name, "findings": [{"severity": "info", "msg": f"Error: {e}"}]})

    for key in selected:
        name, fn = CHECKS[key]
        console.print(f"\n[title]>> {name}[/title]")
        try:
            if key == "sensitive":
                r = fn(requester, args.url, args.wordlist)
            else:
                r = fn(requester, args.url)
            results.append(r)
        except Exception as e:
            console.print(f"[error]x Error in {name}: {e}[/error]")
            results.append({"name": name, "findings": [{"severity": "info", "msg": f"Error: {e}"}]})
    print_results(args.url, results)
    if args.output:
        export_json(args.url, results, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[error]x Interrupted[/error]")
        sys.exit(130)
