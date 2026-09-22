import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
]

def _inject(parsed, param, value, original_query):
    q = original_query.copy()
    q[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

def check_xss(requester, url):
    result = {"name": "Reflected XSS", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(params)} param(s) with {len(PAYLOADS)} payloads...[/info]")
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        marker = f"xss{uuid.uuid4().hex[:6]}"
        for i, payload in enumerate(PAYLOADS, 1):
            test_payload = payload.replace("alert(1)", f"alert('{marker}')")
            test_url = _inject(parsed, param, test_payload, params)
            console.print(f"[dim]      [{i}/{len(PAYLOADS)}] Payload test...[/dim]")
            resp = requester.get(test_url)
            if not resp or not resp.text:
                continue
            if test_payload in resp.text:
                console.print(f"[vuln]    !! VULNERABLE via {param}![/vuln]")
                result["vulnerable"].append({"param": param, "payload": test_payload})
                result["findings"].append({"severity": "high", "msg": f"Reflected XSS via param: {param}"})
                break
    if not result["vulnerable"]:
        console.print("[success]    + No reflected XSS found[/success]")
    return result
