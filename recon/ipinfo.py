import socket
import json
from urllib.request import urlopen, Request
from utils.colors import console


def _resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def check_ipinfo(requester, url):
    from urllib.parse import urlparse
    result = {"name": "IP & Geolocation", "findings": [], "data": {}}
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        console.print("[error]    x Invalid URL[/error]")
        return result

    console.print(f"[info]  -> Resolving {host}...[/info]")
    ip = _resolve_ip(host)
    if not ip:
        console.print("[error]    x Could not resolve[/error]")
        return result

    console.print(f"[success]    + IP: {ip}[/success]")
    result["data"]["ip"] = ip

    # Reverse DNS
    rev = _reverse_dns(ip)
    if rev:
        console.print(f"[success]    + Reverse DNS: {rev}[/success]")
        result["data"]["reverse_dns"] = rev
        result["findings"].append({"severity": "info", "msg": f"IP: {ip} ({rev})"})
    else:
        result["findings"].append({"severity": "info", "msg": f"IP: {ip}"})

    # Geolocation via ip-api.com
    console.print("[dim]    -> Fetching geolocation...[/dim]")
    try:
        req = Request(f"http://ip-api.com/json/{ip}", headers={"User-Agent": "VpiXray/0.1"})
        with urlopen(req, timeout=5) as resp:
            geo = json.loads(resp.read().decode())
        if geo.get("status") == "success":
            country = geo.get("country", "?")
            city = geo.get("city", "?")
            isp = geo.get("isp", "?")
            org = geo.get("org", "?")
            asn = geo.get("as", "?")
            console.print(f"[success]    + Country: {country}[/success]")
            console.print(f"[success]    + City: {city}[/success]")
            console.print(f"[success]    + ISP: {isp}[/success]")
            console.print(f"[success]    + ASN: {asn}[/success]")
            result["data"]["country"] = country
            result["data"]["city"] = city
            result["data"]["isp"] = isp
            result["data"]["org"] = org
            result["data"]["asn"] = asn
            result["findings"].append({
                "severity": "info",
                "msg": f"Location: {city}, {country} | ISP: {isp} | ASN: {asn}",
            })
    except Exception as e:
        console.print(f"[dim]    i Geolocation failed: {e}[/dim]")

    return result
