import re
from utils.colors import console

TECH_SIGNATURES = {
    "WordPress":  [r"wp-content", r"wp-includes"],
    "Joomla":     [r"/components/com_", r"joomla"],
    "Drupal":     [r"sites/default/files", r"Drupal"],
    "React":      [r"__REACT_DEVTOOLS", r"react-dom"],
    "Vue.js":     [r"vue\.js", r"__vue__"],
    "Angular":    [r"ng-version", r"angular"],
    "jQuery":     [r"jquery(\.min)?\.js"],
    "Bootstrap":  [r"bootstrap(\.min)?\.(css|js)"],
    "Nginx":      [r"nginx"],
    "Apache":     [r"apache"],
    "Cloudflare": [r"cloudflare"],
    "PHP":        [r"X-Powered-By:\s*PHP", r"PHPSESSID"],
    "ASP.NET":    [r"ASP\.NET", r"X-AspNet-Version"],
    "Django":     [r"csrftoken", r"django"],
}

def check_fingerprint(requester, url):
    console.print("[info]  -> Analyzing server response...[/info]")
    result = {"name": "Tech Fingerprint", "findings": [], "technologies": []}
    resp = requester.get(url)
    if not resp:
        console.print("[error]    x Connection failed[/error]")
        return result
    haystack = resp.text + "\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    for tech, patterns in TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, haystack, re.IGNORECASE):
                console.print(f"[success]    + Detected: {tech}[/success]")
                result["technologies"].append(tech)
                result["findings"].append({"severity": "info", "msg": f"Detected: {tech}"})
                break
    if not result["technologies"]:
        console.print("[dim]    i No known technologies detected[/dim]")
    return result
