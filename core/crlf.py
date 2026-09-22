from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

CRLF_PAYLOADS = [
    "%0d%0aInjected-Header: vpixray-test",
    "%0aInjected-Header: vpixray-test",
    "%0d%0a%0d%0a<html>injected</html>",
]

def check_crlf(requester, url):
    result = {"name": "CRLF Injection", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(params)} param(s) with {len(CRLF_PAYLOADS)} payloads...[/info]")
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        for i, payload in enumerate(CRLF_PAYLOADS, 1):
            console.print(f"[dim]      [{i}/{len(CRLF_PAYLOADS)}] Testing...[/dim]")
            q = params.copy()
            q[param] = [payload]
            # نبني URL يدويًا لأن urlencode يشوّه %0d%0a
            query = "&".join(f"{k}={v[0]}" for k, v in q.items())
            test_url = urlunparse(parsed._replace(query=query))
            resp = requester.get(test_url)
            if not resp:
                continue
            if "vpixray-test" in resp.headers or "Injected-Header" in str(resp.headers):
                console.print(f"[vuln]    !! CRLF Injection via {param}![/vuln]")
                result["vulnerable"].append({"param": param, "payload": payload})
                result["findings"].append({
                    "severity": "high",
                    "msg": f"CRLF Injection via param: {param}",
                })
                break
    if not result["vulnerable"]:
        console.print("[success]    + No CRLF injection found[/success]")
    return result
