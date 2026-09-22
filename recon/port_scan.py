import socket
from urllib.parse import urlparse
from utils.colors import console

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

DANGEROUS_PORTS = {23, 445, 3306, 3389, 5432, 5900, 6379, 27017}


def _scan_port(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_port_scan(requester, url):
    result = {"name": "Port Scan", "findings": [], "data": {}}
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return result

    console.print(f"[info]  -> Scanning {len(COMMON_PORTS)} common ports on {host}...[/info]")

    open_ports = []
    for port, service in sorted(COMMON_PORTS.items()):
        if _scan_port(host, port):
            open_ports.append((port, service))
            console.print(f"[vuln]    !! {port}/tcp OPEN ({service})[/vuln]")
            result["data"][port] = service
            sev = "high" if port in DANGEROUS_PORTS else "info"
            result["findings"].append({
                "severity": sev,
                "msg": f"Port {port}/tcp open: {service}",
            })

    if not open_ports:
        console.print("[dim]    i No common ports found open[/dim]")
        return result

    console.print(f"[success]    + Total open: {len(open_ports)}[/success]")
    return result
