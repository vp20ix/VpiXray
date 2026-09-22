from utils.colors import console

METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "HEAD"]


def check_http_methods(requester, url):
    result = {"name": "HTTP Methods", "findings": [], "data": {}}
    console.print(f"[info]  -> Testing {len(METHODS)} HTTP methods...[/info]")

    allowed = []
    dangerous = []

    for method in METHODS:
        try:
            resp = requester.session.request(
                method, url,
                timeout=requester.timeout,
                verify=requester.verify,
                allow_redirects=False,
            )
        except Exception:
            console.print(f"[dim]    - {method}: (error)[/dim]")
            continue

        status = resp.status_code
        result["data"][method] = status

        if status in (200, 204, 301, 302, 307, 308, 401, 403):
            console.print(f"[success]    + {method}: {status}[/success]")
            allowed.append(method)

            # TRACE = خطر
            if method == "TRACE" and status == 200:
                dangerous.append("TRACE")
                result["findings"].append({
                    "severity": "high",
                    "msg": "TRACE method enabled (XST attack risk)",
                })

            # PUT/DELETE = خطر
            if method in ("PUT", "DELETE") and status in (200, 204):
                dangerous.append(method)
                result["findings"].append({
                    "severity": "medium",
                    "msg": f"{method} method enabled (file upload/delete risk)",
                })

            # OPTIONS يسمح بعرض الـ Allow header
            if method == "OPTIONS":
                allow = resp.headers.get("Allow", "")
                if allow:
                    console.print(f"[dim]      Allow: {allow}[/dim]")
                    result["data"]["allow_header"] = allow
        else:
            console.print(f"[dim]    - {method}: {status} (not allowed)[/dim]")

    if allowed:
        result["findings"].append({
            "severity": "info",
            "msg": f"Allowed methods: {', '.join(allowed)}",
        })

    if not dangerous:
        console.print("[success]    + No dangerous methods enabled[/success]")

    return result
