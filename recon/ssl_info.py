import socket
import ssl
from urllib.parse import urlparse
from utils.colors import console


def check_ssl(requester, url):
    result = {"name": "SSL/TLS Info", "findings": [], "data": {}}
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return result

    port = parsed.port or 443
    console.print(f"[info]  -> Connecting to {host}:{port} via TLS...[/info]")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
    except Exception as e:
        console.print(f"[error]    x SSL connection failed: {e}[/error]")
        return result

    # Protocol
    console.print(f"[success]    + Protocol: {protocol}[/success]")
    result["data"]["protocol"] = protocol
    result["findings"].append({"severity": "info", "msg": f"Protocol: {protocol}"})

    # Cipher
    if cipher:
        console.print(f"[success]    + Cipher: {cipher[0]}[/success]")
        result["data"]["cipher"] = cipher[0]
        result["findings"].append({"severity": "info", "msg": f"Cipher: {cipher[0]}"})

    # Subject
    subject = dict(x[0] for x in cert.get("subject", []))
    if "commonName" in subject:
        console.print(f"[success]    + Subject CN: {subject['commonName']}[/success]")
        result["data"]["subject_cn"] = subject["commonName"]

    # Issuer
    issuer = dict(x[0] for x in cert.get("issuer", []))
    if "organizationName" in issuer:
        org = issuer["organizationName"]
        console.print(f"[success]    + Issuer: {org}[/success]")
        result["data"]["issuer"] = org
        result["findings"].append({"severity": "info", "msg": f"Issuer: {org}"})

    # Valid dates
    not_before = cert.get("notBefore", "?")
    not_after = cert.get("notAfter", "?")
    console.print(f"[success]    + Valid: {not_before} → {not_after}[/success]")
    result["data"]["not_before"] = not_before
    result["data"]["not_after"] = not_after
    result["findings"].append({
        "severity": "info",
        "msg": f"Cert validity: {not_before} → {not_after}",
    })

    # SAN
    sans = cert.get("subjectAltName", [])
    san_names = [s[1] for s in sans if s[0] == "DNS"][:10]
    if san_names:
        console.print(f"[success]    + SAN: {', '.join(san_names[:5])}[/success]")
        result["data"]["san"] = san_names
        result["findings"].append({"severity": "info", "msg": f"SAN: {', '.join(san_names[:5])}"})

    return result
