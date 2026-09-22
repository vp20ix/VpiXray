from utils.colors import console

def check_cors(requester, url):
    result = {"name": "CORS Misconfig", "findings": [], "vulnerable": []}
    console.print("[info]  -> Sending requests with crafted Origin headers...[/info]")

    origins = [
        "https://evil.example.com",
        "null",
        "http://localhost",
    ]

    for origin in origins:
        console.print(f"[dim]    -> Testing Origin: {origin}[/dim]")
        resp = requester.get(url, headers={"Origin": origin})
        if not resp:
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            console.print(f"[warn]    ! CORS wildcard * (no credentials)[/warn]")
            result["findings"].append({
                "severity": "low",
                "msg": "CORS allows wildcard origin (*) — low risk without credentials",
            })
        elif acao == origin:
            sev = "high" if acac.lower() == "true" else "medium"
            console.print(f"[vuln]    !! CORS reflects Origin: {origin} (credentials: {acac})[/vuln]")
            result["vulnerable"].append({"origin": origin, "credentials": acac})
            result["findings"].append({
                "severity": sev,
                "msg": f"CORS reflects origin '{origin}' (credentials: {acac or 'none'})",
            })

    if not result["findings"]:
        console.print("[success]    + CORS properly configured[/success]")
    return result
