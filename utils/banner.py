from rich.panel import Panel
from utils.colors import console

BANNER = r"""
 ██╗   ██╗██████╗ ██╗██╗  ██╗██████╗  █████╗ ██╗   ██╗
 ██║   ██║██╔══██╗██║╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
 ██║   ██║██████╔╝██║ ╚███╔╝ ██████╔╝███████║ ╚████╔╝ 
 ╚██╗ ██╔╝██╔═══╝ ██║ ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝  
  ╚████╔╝ ██║     ██║██╔╝ ██╗██║  ██║██║  ██║   ██║   
   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
"""

TAGLINE = "[italic dim]X-ray for the web. Nothing hides.[/italic dim]"

def show_banner():
    console.print(f"[title]{BANNER}[/title]")
    console.print(Panel.fit(
        f"[bold white]VpiXray[/bold white] - [cyan]Web Vulnerability Scanner[/cyan]\n"
        f"[dim]v0.1.0 | by vp20ix[/dim]\n\n"
        f"{TAGLINE}",
        border_style="magenta",
        padding=(0, 4),
    ))
