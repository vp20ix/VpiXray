import json
from datetime import datetime, timezone
from rich.table import Table
from rich.panel import Panel
from utils.colors import console

SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim white",
}

def print_results(target, results):
    console.rule(f"[title] VpiXray Report: {target} [/title]")
    for r in results:
        table = Table(title=f"[bold]{r['name']}[/bold]", expand=False)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Details", overflow="fold")
        if not r["findings"]:
            table.add_row("[dim]info[/dim]", "[dim]No findings[/dim]")
        else:
            for f in r["findings"]:
                sev = f["severity"]
                table.add_row(f"[{SEV_COLOR.get(sev,'white')}]{sev}[/]", f["msg"])
        console.print(table)
        console.print()
    _print_summary(results)

def _print_summary(results):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        for f in r["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = (
        f"[bold red]Critical:[/] {counts['critical']}   "
        f"[red]High:[/] {counts['high']}   "
        f"[yellow]Medium:[/] {counts['medium']}   "
        f"[cyan]Low:[/] {counts['low']}   "
        f"[dim]Info:[/] {counts['info']}"
    )
    console.print(Panel(summary, title="[title]Summary[/title]", border_style="magenta"))

def export_json(target, results, path):
    data = {
        "tool": "VpiXray",
        "version": "0.1.0",
        "author": "vp20ix",
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    console.print(f"[success]OK Report exported: {path}[/success]")
