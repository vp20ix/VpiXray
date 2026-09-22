from utils.colors import console

CDN_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
    "Akamai": ["akamai", "ak-bmsc"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
    "Fastly": ["fastly", "x-served-by"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "Incapsula": ["incap_ses", "visid_incap"],
    "Vercel": ["vercel", "x-vercel-id"],
    "Netlify": ["netlify", "x-nf-request-id"],
}

SERVER_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Via"]


def check_server_info(requester, url):
    result = {"name": "Server Info", "findings": [], "data": {}}
    console.print("[info]  -> Analyzing server headers...[/info]")
    resp = requester.get(url)
    if not resp:
        console.print("[error]    x Connection failed[/error]")
        return result

    # Server headers
    for header in SERVER_HEADERS:
        value = resp.headers.get(header)
        if value:
            console.print(f"[success]    + {header}: {value}[/success]")
            result["data"][header] = value
            result["findings"].append({"severity": "info", "msg": f"{header}: {value}"})

    # CDN detection
    headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
    cookies = resp.headers.get("Set-Cookie", "").lower()
    combined = headers_str + " " + cookies

    for cdn, sigs in CDN_SIGNATURES.items():
        for sig in sigs:
            if sig in combined:
                console.print(f"[success]    + CDN/WAF detected: {cdn}[/success]")
                result["data"]["cdn"] = cdn
                result["findings"].append({"severity": "info", "msg": f"CDN/WAF: {cdn}"})
                break
        if "cdn" in result["data"]:
            break

    # Security indicator
    if "Server" in result["data"]:
        server = result["data"]["Server"]
        result["findings"].append({
            "severity": "low",
            "msg": f"Server banner exposed: {server} (info disclosure)",
        })

    if not result["data"]:
        console.print("[dim]    i No server info headers found[/dim]")

    return result
