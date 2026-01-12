import asyncio
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.text import Text
from rich.align import Align
import pyfiglet

console = Console()

def print_banner():
    banner = pyfiglet.figlet_format("SubEnum", font="slant")
    console.print(Panel(Align.center(Text(banner, style="bold cyan")), border_style="blue"))
    console.print(Align.center("[bold green]High-Performance Async Subdomain Enumerator[/bold green]"))
    console.print(Align.center("[white]Built for speed & cool vibes[/white]\n"))

class ScanDashboard:
    def __init__(self):
        self.layout = Layout()
        self.setup_layout()
        
        self.found_count = 0
        self.total_scanned = 0
        self.start_time = datetime.now()
        self.results_table = Table(title="Found Subdomains", expand=True, style="cyan")
        self.results_table.add_column("Timestamp", style="dim", width=12)
        self.results_table.add_column("Subdomain", style="bold white")
        self.results_table.add_column("IP Address", style="green")
        self.results_table.add_column("CNAME", style="yellow")
        
        self.log_content = [] 
        
    def setup_layout(self):
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=7)
        )
        self.layout["main"].split_row(
            Layout(name="results", ratio=2),
            Layout(name="sidebar", ratio=1)
        )
        self.layout["header"].update(Panel(Text("Scanning...", justify="center", style="bold white"), style="blue"))

    def add_result(self, result: dict):
        self.found_count += 1
        ts = result.get("timestamp", "").split("T")[-1][:8] # HH:MM:SS
        ips = ", ".join(result.get("ip_addresses", []))
        cname = result.get("cname", "")
        self.results_table.add_row(ts, result["subdomain"], ips, cname)

    def update_stats(self, scanned_count, rate_limit):
        self.total_scanned = scanned_count
        elapsed = (datetime.now() - self.start_time).total_seconds()
        rate = scanned_count / elapsed if elapsed > 0 else 0
        
        stats_text = f"""
[bold]Status:[/bold] [green]Running[/green]
[bold]Found:[/bold] {self.found_count}
[bold]Scanned:[/bold] {self.total_scanned}
[bold]Elapsed:[/bold] {elapsed:.1f}s
[bold]Avg Rate:[/bold] {rate:.1f} req/s
[bold]Workers:[/bold] {rate_limit}
"""
        self.layout["sidebar"].update(Panel(stats_text, title="Statistics", border_style="green"))
        self.layout["results"].update(Panel(self.results_table, title="Live Results", border_style="cyan"))

    def log(self, message):
        # In a real TUI we might append to a list and show last N lines
        # For now, just a simple status update in footer or similar?
        # Let's put logs in the footer
        self.log_content.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        if len(self.log_content) > 5:
            self.log_content.pop(0)
        
        log_text = "\n".join(self.log_content)
        self.layout["footer"].update(Panel(log_text, title="System Logs", style="dim"))

    def get_layout(self):
        return self.layout
