from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.colors import console

def check_idor(requester, url):
    result = {"name": "IDOR", "findings": [], "vulnerable": []}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    numeric_params = {k: v for k, v in params.items() if v and v[0].isdigit()}
    if not numeric_params:
        console.print("[dim]    i No numeric parameters found, skipping[/dim]")
        return result
    console.print(f"[info]  -> Testing {len(numeric_params)} numeric param(s) for IDOR...[/info]")
    for param, values in numeric_params.items():
        original_id = int(values[0])
        console.print(f"[dim]    -> Param: {param} (id={original_id})[/dim]")
        for test_id in [original_id - 1, original_id + 1, original_id + 100, 1, 0]:
            if test_id < 0 or test_id == original_id:
                continue
            q = params.copy()
            q[param] = [str(test_id)]
            test_url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            resp = requester.get(test_url)
            if resp and resp.status_code == 200 and len(resp.text) > 100:
                console.print(f"[warn]    ? Different response for {param}={test_id} (potential IDOR)[/warn]")
                result["findings"].append({
                    "severity": "medium",
                    "msg": f"Possible IDOR via {param}={test_id} (manual verification needed)",
                })
                break
    if not result["findings"]:
        console.print("[success]    + No obvious IDOR found[/success]")
    return result
