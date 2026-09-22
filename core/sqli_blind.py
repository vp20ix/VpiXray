from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

TRUE_PAYLOADS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
]

def _inject(parsed, param, value, original_query):
    q = original_query.copy()
    q[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(q, doseq=True)))

def check_sqli_blind(requester, url):
    result = {"name": "Blind SQLi (Boolean)", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        console.print("[dim]    i No parameters found, skipping[/dim]")
        return result

    console.print(f"[info]  -> Testing {len(params)} param(s) with True/False payloads...[/info]")
    for param in params:
        console.print(f"[dim]    -> Param: {param}[/dim]")
        for true_p, false_p in TRUE_PAYLOADS:
            console.print(f"[dim]      Testing: {true_p} vs {false_p}[/dim]")
            true_url = _inject(parsed, param, true_p, params)
            false_url = _inject(parsed, param, false_p, params)

            r_true = requester.get(true_url)
            r_false = requester.get(false_url)
            if not r_true or not r_false:
                continue

            len_diff = abs(len(r_true.text) - len(r_false.text))
            # فرق كبير = محتمل Blind SQLi
            if len_diff > 50 and r_true.status_code == r_false.status_code:
                console.print(f"[vuln]    !! Blind SQLi possible via {param}! (diff: {len_diff} bytes)[/vuln]")
                result["vulnerable"].append({"param": param, "true_p": true_p, "diff": len_diff})
                result["findings"].append({
                    "severity": "critical",
                    "msg": f"Blind SQLi via param: {param} (True/False diff: {len_diff} bytes)",
                })
                break
    if not result["vulnerable"]:
        console.print("[success]    + No blind SQLi found[/success]")
    return result
