import os
from utils.colors import console

DEFAULT_FILES = [
    ".env", ".git/config", ".git/HEAD", "backup.zip", "backup.tar.gz",
    "config.php.bak", "wp-config.php.bak", ".DS_Store", "phpinfo.php",
    "admin/", "robots.txt", "sitemap.xml", ".htaccess", "web.config",
    "composer.json", "package.json", "Dockerfile", ".dockerignore",
]

def load_wordlist(path=None):
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return DEFAULT_FILES

def check_sensitive(requester, base_url, wordlist_path=None):
    files = load_wordlist(wordlist_path)
    console.print(f"[info]  -> Testing {len(files)} sensitive paths...[/info]")
    result = {"name": "Sensitive Files", "findings": [], "hits": []}
    base = base_url.rstrip("/")
    hits = 0
    for i, path in enumerate(files, 1):
        url = f"{base}/{path}"
        console.print(f"[dim]    [{i}/{len(files)}] -> /{path}[/dim]")
        resp = requester.get(url)
        if resp and resp.status_code in (200, 301, 302, 403):
            size = len(resp.content)
            hits += 1
            result["hits"].append({"url": url, "status": resp.status_code, "size": size})
            sev = "high" if resp.status_code == 200 else "low"
            console.print(f"[vuln]    !! HIT [{resp.status_code}] {url} ({size} bytes)[/vuln]")
            result["findings"].append({
                "severity": sev,
                "msg": f"[{resp.status_code}] {url} ({size} bytes)",
            })
    if hits == 0:
        console.print("[success]    + No sensitive files exposed[/success]")
    else:
        console.print(f"[error]    !! {hits} sensitive file(s) found[/error]")
    return result
