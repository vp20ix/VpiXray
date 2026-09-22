from utils.colors import console

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


def check_whois(requester, url):
    from urllib.parse import urlparse
    result = {"name": "WHOIS", "findings": [], "data": {}}

    if not HAS_WHOIS:
        console.print("[error]    x python-whois not installed[/error]")
        return result

    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return result

    # نظّف الدومين (شيل www)
    if host.startswith("www."):
        host = host[4:]

    console.print(f"[info]  -> Querying WHOIS for {host}...[/info]")

    try:
        w = whois.whois(host)
    except Exception as e:
        console.print(f"[error]    x WHOIS failed: {e}[/error]")
        return result

    fields = {
        "registrar": "Registrar",
        "creation_date": "Created",
        "expiration_date": "Expires",
        "updated_date": "Updated",
        "name_servers": "Name Servers",
        "status": "Status",
        "emails": "Emails",
    }

    for key, label in fields.items():
        value = getattr(w, key, None)
        if not value:
            continue
        if isinstance(value, list):
            value = value[0] if key != "name_servers" and key != "status" else value
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value[:5])
        value = str(value)
        result["data"][key] = value
        console.print(f"[success]    + {label}: {value}[/success]")
        result["findings"].append({"severity": "info", "msg": f"{label}: {value}"})

    if not result["data"]:
        console.print("[warn]    ! No WHOIS data available[/warn]")

    return result
