from utils.colors import console

COMMON_DIRS = [
    "/", "/images/", "/uploads/", "/files/", "/backup/",
    "/admin/", "/assets/", "/static/", "/css/", "/js/",
    "/logs/", "/tmp/", "/data/",
]

def check_dirlisting(requester, base_url):
    result = {"name": "Directory Listing", "findings": [], "vulnerable": []}
    base = base_url.rstrip("/")
    console.print(f"[info]  -> Testing {len(COMMON_DIRS)} directories...[/info]")

    for i, path in enumerate(COMMON_DIRS, 1):
        url = f"{base}{path}"
        console.print(f"[dim]    [{i}/{len(COMMON_DIRS)}] {path}[/dim]")
        resp = requester.get(url)
        if not resp or resp.status_code != 200:
            continue
        body = resp.text.lower()
        if "<title>index of" in body or "<h1>index of" in body:
            console.print(f"[vuln]    !! Directory listing enabled: {path}[/vuln]")
            result["vulnerable"].append({"path": path})
            result["findings"].append({
                "severity": "medium",
                "msg": f"Directory listing enabled: {path}",
            })

    if not result["vulnerable"]:
        console.print("[success]    + No directory listing found[/success]")
    return result
