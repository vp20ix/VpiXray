from bs4 import BeautifulSoup
from utils.colors import console

def check_csrf(requester, url):
    result = {"name": "CSRF", "findings": [], "vulnerable": []}
    console.print("[info]  -> Scanning for forms...[/info]")
    resp = requester.get(url)
    if not resp:
        console.print("[error]    x Connection failed[/error]")
        return result
    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")
    console.print(f"[dim]    Found {len(forms)} form(s)[/dim]")
    for i, form in enumerate(forms, 1):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.find_all("input")
        has_token = False
        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if "token" in name or "csrf" in name or "_token" in name:
                has_token = True
                break
        if method == "POST" and not has_token:
            console.print(f"[vuln]    !! Form #{i} POST without CSRF token[/vuln]")
            result["vulnerable"].append({"form": i, "action": action, "method": method})
            result["findings"].append({
                "severity": "medium",
                "msg": f"POST form without CSRF token (action: {action or 'same page'})",
            })
        else:
            console.print(f"[success]    + Form #{i} OK ({method}, token: {has_token})[/success]")
    if not result["vulnerable"]:
        console.print("[success]    + No CSRF issues found[/success]")
    return result
