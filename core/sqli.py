from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlite3.operationalerror",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
]

PAYLOADS = ["'", '"', "')", "';--", '" OR "1"="1']

def _inject(parsed, param, value, original_query):
    q = original_query.copy()
    q[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

def check_sqli(requester, url):
    result = {"name": "SQL Injection", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result

    console.print(f"[info]  -> Testing {len(params)} param(s) with {len(PAYLOADS)} payloads...[/info]")
    found_params = set()
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        if param in found_params:
            continue
        for i, payload in enumerate(PAYLOADS, 1):
            console.print(f"[dim]      [{i}/{len(PAYLOADS)}] Payload: {payload!r}[/dim]")
            test_url = _inject(parsed, param, payload, params)
            resp = requester.get(test_url)
            if not resp or not resp.text:
                continue
            body = resp.text.lower()
            for pattern in ERROR_PATTERNS:
                if pattern in body:
                    console.print(f"[vuln]    !! SQLi possible via {param}! Pattern: {pattern}[/vuln]")
                    result["vulnerable"].append({"param": param, "payload": payload, "pattern": pattern})
                    result["findings"].append({
                        "severity": "critical",
                        "msg": f"SQLi possible via param: {param} (payload: {payload})",
                    })
                    found_params.add(param)
                    break
            if param in found_params:
                break
    if not result["vulnerable"]:
        console.print("[success]    + No error-based SQLi found[/success]")
    return result

# ============ Time-based SQLi ============
import time as _time

TIME_PAYLOADS = [
    ("' AND SLEEP(5)-- -", 5),
    ("' AND SLEEP(5)#", 5),
    ("' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -", 5),
]

def check_sqli_time(requester, url):
    result = {"name": "Time-based SQLi", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(params)} param(s) for time-based SQLi...[/info]")
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        base_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        t0 = _time.time()
        requester.get(base_url)
        baseline = _time.time() - t0
        console.print(f"[dim]      Baseline: {baseline:.2f}s[/dim]")
        for payload, delay in TIME_PAYLOADS:
            q = params.copy()
            q[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            t0 = _time.time()
            resp = requester.get(test_url)
            elapsed = _time.time() - t0
            console.print(f"[dim]      Delay: {elapsed:.2f}s[/dim]")
            if elapsed > (baseline + delay - 1):
                console.print(f"[vuln]    !! Time-based SQLi via {param}! ({elapsed:.2f}s)[/vuln]")
                result["vulnerable"].append({"param": param, "payload": payload, "delay": elapsed})
                result["findings"].append({
                    "severity": "critical",
                    "msg": f"Time-based SQLi via param: {param} ({elapsed:.2f}s)",
                })
                break
    if not result["vulnerable"]:
        console.print("[success]    + No time-based SQLi found[/success]")
    return result
