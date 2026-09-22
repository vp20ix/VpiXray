import base64
import json
import re
from utils.colors import console

JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")

def _b64decode_pad(s):
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def check_jwt(requester, url):
    result = {"name": "JWT Analyzer", "findings": [], "vulnerable": []}
    console.print("[info]  -> Scanning for JWT tokens in response...[/info]")
    resp = requester.get(url)
    if not resp:
        console.print("[error]    x Connection failed[/error]")
        return result

    # ندور في الرد والـ headers
    haystack = resp.text + "\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    tokens = set(JWT_REGEX.findall(haystack))

    if not tokens:
        console.print("[dim]    i No JWT tokens found[/dim]")
        return result

    console.print(f"[dim]    Found {len(tokens)} JWT token(s)[/dim]")

    for token in tokens:
        parts = token.split(".")
        if len(parts) != 3:
            continue

        header = _b64decode_pad(parts[0])
        payload = _b64decode_pad(parts[1])
        console.print(f"[dim]    Header: {header[:100]}[/dim]")
        console.print(f"[dim]    Payload: {payload[:100]}[/dim]")

        try:
            header_json = json.loads(header)
            alg = header_json.get("alg", "").lower()
        except Exception:
            alg = ""

        if alg == "none":
            console.print("[vuln]    !! JWT with 'alg: none'![/vuln]")
            result["findings"].append({
                "severity": "critical",
                "msg": "JWT uses 'alg: none' (signature bypass)",
            })
            result["vulnerable"].append({"issue": "alg_none"})

        if alg in ("hs256", "hs384", "hs512"):
            console.print(f"[warn]    ! JWT uses {alg.upper()} (test weak secret)[/warn]")
            result["findings"].append({
                "severity": "low",
                "msg": f"JWT uses HMAC ({alg}) — test for weak secret",
            })

        try:
            payload_json = json.loads(payload)
            if "exp" not in payload_json:
                console.print("[warn]    ! JWT has no expiration (exp)[/warn]")
                result["findings"].append({
                    "severity": "medium",
                    "msg": "JWT has no 'exp' claim",
                })
        except Exception:
            pass

    if not result["findings"]:
        console.print("[success]    + No JWT issues found[/success]")
    return result
