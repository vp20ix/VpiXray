from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
    "http://localhost:8080/",
]

URL_PARAM_HINTS = ["url", "uri", "link", "src", "dest", "redirect", "path", "file", "load", "fetch"]

def check_ssrf(requester, url):
    result = {"name": "SSRF", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    url_params = {k: v for k, v in params.items() if any(h in k.lower() for h in URL_PARAM_HINTS)}
    if not url_params:
        console.print("[dim]    i No URL-like parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(url_params)} URL param(s)...[/info]")
    for param in url_params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        for payload in SSRF_PAYLOADS:
            q = params.copy()
            q[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            console.print(f"[dim]      Testing: {payload}[/dim]")
            resp = requester.get(test_url)
            if resp and ("root:" in resp.text or "meta-data" in resp.text or "instance-id" in resp.text):
                console.print(f"[vuln]    !! SSRF via {param}![/vuln]")
                result["vulnerable"].append({"param": param, "payload": payload})
                result["findings"].append({"severity": "critical", "msg": f"SSRF via param: {param}"})
                break
    if not result["vulnerable"]:
        console.print("[success]    + No SSRF found[/success]")
    return result
