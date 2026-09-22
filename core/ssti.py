from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("{{'7'*7}}", "7777777"),
]

def check_ssti(requester, url):
    result = {"name": "SSTI", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(params)} param(s) with {len(SSTI_PAYLOADS)} payloads...[/info]")
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        for i, (payload, expected) in enumerate(SSTI_PAYLOADS, 1):
            console.print(f"[dim]      [{i}/{len(SSTI_PAYLOADS)}] {payload}[/dim]")
            q = params.copy()
            q[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            resp = requester.get(test_url)
            if resp and expected in resp.text and payload not in resp.text:
                console.print(f"[vuln]    !! SSTI via {param}! ({payload} => {expected})[/vuln]")
                result["vulnerable"].append({"param": param, "payload": payload})
                result["findings"].append({
                    "severity": "critical",
                    "msg": f"SSTI via param: {param} ({payload} evaluated)",
                })
                break
    if not result["vulnerable"]:
        console.print("[success]    + No SSTI found[/success]")
    return result
