import json
from urllib.request import urlopen, Request
from urllib.parse import urlparse
from utils.colors import console


def check_subdomains(requester, url):
    result = {"name": "Subdomain Enum", "findings": [], "data": {}}
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return result

    # ناخذ الدومين الأساسي
    parts = host.split(".")
    if len(parts) > 2:
        base_domain = ".".join(parts[-2:])
    else:
        base_domain = host

    console.print(f"[info]  -> Querying crt.sh for *.​{base_domain}...[/info]")

    try:
        api_url = f"https://crt.sh/?q=%25.{base_domain}&output=json"
        req = Request(api_url, headers={"User-Agent": "VpiXray/0.1"})
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        console.print(f"[error]    x crt.sh failed: {e}[/error]")
        return result

    subs = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            line = line.strip().lower()
            if line and "*" not in line and line.endswith(base_domain):
                subs.add(line)

    subs = sorted(subs)
    if not subs:
        console.print("[dim]    i No subdomains found[/dim]")
        return result

    console.print(f"[success]    + Found {len(subs)} subdomain(s):[/success]")
    for sub in subs[:30]:
        console.print(f"[dim]      - {sub}[/dim]")
        result["findings"].append({"severity": "info", "msg": f"Subdomain: {sub}"})

    if len(subs) > 30:
        console.print(f"[dim]      ... and {len(subs) - 30} more[/dim]")

    result["data"]["subdomains"] = subs
    return result
