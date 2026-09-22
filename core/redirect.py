from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "https://evil.example.com/%2f..",
    "/\\evil.example.com",
]

def _build_url(parsed, param, value, original_query):
    q = original_query.copy()
    q[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

def check_redirect(requester, url):
    result = {"name": "Open Redirect", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(params)} param(s) with {len(PAYLOADS)} payloads...[/info]")
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        for payload in PAYLOADS:
            test_url = _build_url(parsed, param, payload, params)
            resp = requester.get(test_url)
            if not resp:
                continue
            loc = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and "evil.example.com" in loc:
                console.print(f"[vuln]    !! VULNERABLE via {param}![/vuln]")
                result["vulnerable"].append({"param": param, "payload": payload, "location": loc})
                result["findings"].append({"severity": "high", "msg": f"Open Redirect via param: {param}"})
                break
    if not result["vulnerable"]:
        console.print("[success]    + No open redirect found[/success]")
    return result
