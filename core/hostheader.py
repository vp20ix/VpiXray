from utils.colors import console

def check_host_header(requester, url):
    result = {"name": "Host Header Injection", "findings": [], "vulnerable": []}
    console.print("[info]  -> Testing Host header manipulation...[/info]")

    evil_hosts = [
        "evil.example.com",
        "localhost",
    ]

    for host in evil_hosts:
        console.print(f"[dim]    -> Testing Host: {host}[/dim]")
        resp = requester.get(url, headers={"Host": host})
        if not resp:
            continue
        body = resp.text.lower()
        if "evil.example.com" in body or host in body:
            console.print(f"[vuln]    !! Host header reflected in response: {host}[/vuln]")
            result["vulnerable"].append({"host": host})
            result["findings"].append({
                "severity": "high",
                "msg": f"Host header '{host}' reflected in response (password reset poisoning risk)",
            })
            break

    if not result["vulnerable"]:
        console.print("[success]    + Host header not reflected[/success]")
    return result
