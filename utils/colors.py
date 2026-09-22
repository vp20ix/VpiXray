from rich.console import Console
from rich.theme import Theme

theme = Theme({
    "info":    "cyan",
    "success": "bold green",
    "warn":    "bold yellow",
    "error":   "bold red",
    "vuln":    "bold red on white",
    "title":   "bold magenta",
    "dim":     "dim white",
})

console = Console(theme=theme)
