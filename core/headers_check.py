from utils.colors import console

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS",
    "Content-Security-Policy":   "Mitigates XSS",
    "X-Frame-Options":           "Prevents Clickjacking",
    "X-Content-Type-Options":    "Prevents MIME sniffing",
    "Referrer-Policy":           "Controls referrer leakage",
    "Permissions-Policy":        "Restricts browser features",
    "Cross-Origin-Opener-Policy":"Isolates windows",
    "Cross-Origin-Resource-Policy":"Blocks cross-origin loads",
}

def check_headers(requester, url):
    console.print("[info]  -> Fetching HTTP headers...[/info]")
    result = {"name": "Security Headers", "findings": [], "missing": [], "score": 0}
    resp = requester.get(url)
    if not resp:
        console.print("[error]    x Connection failed[/error]")
        result["findings"].append({"severity": "info", "msg": "Could not connect"})
        return result
    console.print("[dim]    OK Response received, analyzing...[/dim]")
    present = 0
    lower_keys = {k.lower() for k in resp.headers.keys()}
    for header, desc in SECURITY_HEADERS.items():
        if header.lower() in lower_keys:
            console.print(f"[success]    + {header}[/success]")
            present += 1
        else:
            console.print(f"[warn]    - {header} MISSING[/warn]")
            result["missing"].append({"header": header, "desc": desc})
    result["score"] = int((present / len(SECURITY_HEADERS)) * 100)
    if result["missing"]:
        result["findings"].append({
            "severity": "low" if result["score"] > 50 else "medium",
            "msg": f"{len(result['missing'])} missing security headers (score: {result['score']}%)",
        })
    return result
