from utils.colors import console

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def check_dns(requester, url):
    from urllib.parse import urlparse
    result = {"name": "DNS Records", "findings": [], "data": {}}

    if not HAS_DNS:
        console.print("[error]    x dnspython not installed[/error]")
        return result

    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        console.print("[error]    x Invalid URL[/error]")
        return result

    console.print(f"[info]  -> Querying DNS records for {host}...[/info]")

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=5)
            records = [str(a).strip('"') for a in answers]
            result["data"][rtype] = records
            console.print(f"[success]    + {rtype}: {', '.join(records[:3])}{'...' if len(records) > 3 else ''}[/success]")
            result["findings"].append({
                "severity": "info",
                "msg": f"{rtype}: {', '.join(records[:5])}",
            })
        except dns.resolver.NoAnswer:
            console.print(f"[dim]    - {rtype}: (no records)[/dim]")
        except dns.resolver.NXDOMAIN:
            console.print(f"[error]    x Domain does not exist[/error]")
            break
        except Exception as e:
            console.print(f"[dim]    - {rtype}: ({e.__class__.__name__})[/dim]")

    if not result["data"]:
        console.print("[warn]    ! No DNS records found[/warn]")

    return result
