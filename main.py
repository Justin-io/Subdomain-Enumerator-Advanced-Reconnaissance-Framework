import asyncio
import argparse
import sys
import logging
import json
import csv
import os
from datetime import datetime
from dotenv import load_dotenv

# Import our modules
from utils.system_checks import check_ulimit
from modules.wordlist_gen import WordlistGenerator
from modules.dns_resolver import ResolverEngine
from modules.wildcard import WildcardDetector
from modules.probes import HTTPProber
from modules.ui import ScanDashboard, print_banner
from modules.ai import AIAnalyst
from modules.passive import PassiveRecon
from modules.port_scanner import PortScanner
from modules.reporting import ReportGenerator
from modules.injector import VulnScanner
from modules.takeover import TakeoverDetector
from modules.fuzzer import Fuzzer
from modules.fingerprint import Fingerprinter
from modules.js_analyzer import JSAnalyzer
from modules.archives import ArchiveFetcher
from modules.spider import OmniscientSpider
from modules.mutator import SubdomainMutator

from rich.live import Live
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.prompt import Prompt
import readchar

# Load Environment Variables
load_dotenv()

# Configure Console
console = Console()

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.FileHandler("subenum.log")]
)
logger = logging.getLogger("SubEnum")

async def worker(queue, resolver, wildcard, prober, port_scanner, injector, takeover, fuzzer, fingerprinter, js_analyzer, spider, mutator, results, seen_subdomains, do_probe, do_ports, do_inject, do_audit, do_elite, do_omni, ui_callback):
    """
    Consumer worker that processes subdomains from the queue.
    """
    while True:
        subdomain = await queue.get()
        try:
            # 1. Resolve
            res = await resolver.resolve(subdomain, 'A')
            if res:
                ips = [r.host for r in res]
                
                if wildcard.is_false_positive(ips):
                    queue.task_done()
                    ui_callback("scanned")
                    continue
                
                cname = ""
                res_cname = await resolver.resolve(subdomain, 'CNAME')
                if res_cname:
                    cname = res_cname.cname

                obj = {
                    "subdomain": subdomain,
                    "ip_addresses": ips,
                    "cname": cname,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "source": "bruteforce"
                }

                # 2. HTTP Probe
                http_data = None
                if do_probe or do_inject or do_audit or do_elite or do_omni:
                    http_data = await prober.probe(subdomain)
                    if http_data:
                        obj.update(http_data)
                
                # 3. Active Port Scan
                if do_ports and ips:
                    open_ports = await port_scanner.scan(ips[0])
                    obj["open_ports"] = open_ports

                # 4. Auto Injection (Vuln Scan)
                if do_inject and http_data and http_data.get("url"):
                    vulns = await injector.scan(http_data["url"])
                    if vulns:
                        obj["vulnerabilities"] = vulns
                        
                # 5. Specialist Audit (Takeover, Fuzzing, Fingerprint)
                if do_audit:
                    # 1. Takeover
                    takeover_res = await takeover.check(subdomain, cname, http_data.get("url") if http_data else None)
                    if takeover_res:
                         obj["takeover"] = takeover_res
                    
                    if http_data and http_data.get("url"):
                        target_url = http_data["url"]
                        
                        # 2. Fingerprinting
                        tech = await fingerprinter.identify(target_url)
                        if tech:
                            obj["technologies"] = tech
                            
                        # 3. Fuzzing
                        fuzz_res = await fuzzer.fuzz(target_url)
                        if fuzz_res:
                            obj["sensitive_files"] = fuzz_res
                
                # 6. Elite Recon (JS Analysis)
                if do_elite and http_data and http_data.get("url"):
                     js_findings = await js_analyzer.analyze(http_data["url"])
                     if js_findings:
                         obj["js_secrets"] = js_findings

                # 7. OMNISCIENT (Spidering & Mutation)
                if do_omni and http_data and http_data.get("url"):
                    # Spider for new subdomains in HTML
                    html = http_data.get("body", "") # prober captures body
                    discovered_subs = spider.extract_subdomains(html)
                    
                    # Generate mutations
                    mutations = mutator.mutate(subdomain)
                    discovered_subs.update(mutations)
                    
                    # RECURSIVE INJECTION
                    for s in discovered_subs:
                        if s not in seen_subdomains:
                            seen_subdomains.add(s)
                            queue.put_nowait(s)
                            logger.info(f"O_O Omniscient Discovery: {s}")

                logger.info(f"FOUND: {subdomain} -> {ips} {cname}")
                results.append(obj)
                ui_callback("found", obj)
            
            ui_callback("scanned")

        except Exception as e:
            logger.debug(f"Error processing {subdomain}: {e}")
            ui_callback("scanned")
        finally:
            queue.task_done()

def export_results(results, output_file, format="json"):
    if format == "json":
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Results saved to {output_file}[/green]")
    elif format == "csv":
        csv_file = output_file.replace(".json", ".csv")
        if results:
            keys = results[0].keys()
            with open(csv_file, "w", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(results)
        console.print(f"[green]Results saved to {csv_file}[/green]")

async def interactive_menu(results, ai_analyst, args):
    reporter = ReportGenerator()
    last_ai_report = ""

    while True:
        console.print("\n[bold cyan]Post-Scan Actions:[/bold cyan]")
        console.print("[A] Analyze Results with AI")
        console.print("[R] Generate HTML Report")
        console.print("[E] Export Results (CSV)")
        console.print("[Q] Quit")
        
        console.print("\n[dim]Press a key...[/dim]", end="")
        key = readchar.readkey().lower()
        print(key)

        if key == 'a':
            console.print("\n[bold yellow]🤖 Analyzing findings with AI...[/bold yellow]")
            with console.status("[bold green]Thinking...[/bold green]"):
                last_ai_report = ai_analyst.analyze(results)
            console.print(Panel(Markdown(last_ai_report), title="AI Security Report", border_style="magenta"))
        
        elif key == 'r':
            filename = reporter.generate(args.domain, results, ai_report=last_ai_report)
            console.print(f"\n[bold green]Report generated: {filename}[/bold green]")
            console.print("[dim]Open this file in your browser.[/dim]")

        elif key == 'e':
            export_results(results, args.output, format="csv")
        
        elif key == 'q':
            console.print("[bold red]Exiting. Happy Hacking![/bold red]")
            break

async def main():
    parser = argparse.ArgumentParser(description="Next-Level Async Subdomain Enumerator")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("--rate", type=int, default=100, help="Concurrency limit")
    parser.add_argument("--probe", action="store_true", help="Enable HTTP probing")
    parser.add_argument("--ports", action="store_true", help="Enable Active Port Scanning")
    parser.add_argument("--inject", action="store_true", help="Enable Auto Injection (Vuln Scan) [WARNING: ACTIVE ATTACK]")
    parser.add_argument("--audit", action="store_true", help="Enable Specialist Audit (Takeover, Fuzzer, Fingerprint) [PRO MODE]")
    parser.add_argument("--elite", action="store_true", help="Enable ELITE RECON (JS Secrets, Archives, AXFR) [POWER MODE]")
    parser.add_argument("--omni", action="store_true", help="Enable OMNISCIENT Mode (Recursive Spidering & Mutations) [GOD MODE]")
    parser.add_argument("--output", default="results.json", help="Output file (JSON)")
    parser.add_argument("--csv", action="store_true", help="Auto-export CSV")
    parser.add_argument("--lax", action="store_true", help="Disable strict wildcard filtering")
    args = parser.parse_args()

    print_banner()

    if args.inject or args.audit or args.elite or args.omni:
        console.print("[bold red blink]!!! WARNING: ACTIVE ATTACK MODE ENABLED !!![/bold red blink]")
        if args.inject:
             console.print("[red]--inject: Sending exploit payloads (XSS, SQLi).[/red]")
        if args.audit:
             console.print("[red]--audit: Fuzzing sensitive files and checking takeovers.[/red]")
        if args.elite:
             console.print("[red]--elite: Deep scraping JS secrets, Wayback Machine, and DNS Zones.[/red]")
        if args.omni:
             console.print("[red]--omni: GOD MODE. Autonomous recursive spidering and mutations.[/red]")
        console.print("[red]Ensure you have explicit permission to audit this target.[/red]\n")
        await asyncio.sleep(2)

    ai_analyst = AIAnalyst()
    passive_recon = PassiveRecon()
    
    # 1. System Check
    check_ulimit(min_limit=args.rate + 100)
    
    # 2. Passive Recon (OSINT)
    # Standard CRT.sh
    console.print(f"[+] Starting Passive Recon via CRT.sh...")
    passive_subs = await passive_recon.fetch_crt_sh(args.domain)
    console.print(f"[green]✔ CRT.sh found {len(passive_subs)} subdomains[/green]")

    # ELITE: DNS Zone Availability check + Recursive Passive
    if args.elite or args.omni:
        console.print(f"[+] [ELITE] Attempting DNS Zone Transfer (AXFR)...")
        axfr_subs = await passive_recon.check_axfr(args.domain)
        if axfr_subs:
            console.print(f"[bold red]✔ AXFR SUCCESS: Found {len(axfr_subs)} subdomains![/bold red]")
            passive_subs.update(axfr_subs)
        else:
             console.print(f"[dim]✘ AXFR failed (expected).[/dim]")

        console.print(f"[+] [ELITE] Fetching Historical URLs via Wayback Machine...")
        archives = ArchiveFetcher()
        # This is async but we don't scan them yet, just finding extra subdomains potentially from URL list?
        # Actually archive fetcher returns URLs. We can extract subdomains from them.
        hist_urls = await archives.fetch_history(args.domain)
        console.print(f"[green]✔ Wayback Machine found {len(hist_urls)} endpoints[/green]")
        # Extract subdomains from history
        for u in hist_urls:
            try:
                # simple parse
                from urllib.parse import urlparse
                if "//" in u:
                    parsed = urlparse(u)
                    if parsed.netloc.endswith(args.domain):
                        passive_subs.add(parsed.netloc)
            except: pass


    # 3. Load Wordlist
    console.print(f"[+] Loading wordlist from {args.wordlist}...")
    try:
        wl_gen = WordlistGenerator(args.wordlist)
        base_words = wl_gen.load()
    except Exception as e:
        console.print(f"[!] Error: {str(e)}")
        sys.exit(1)

    # 4. Prepare Subdomains
    target_subdomains = {f"{w}.{args.domain}" for w in base_words}
    all_subdomains = target_subdomains.union(passive_subs)
    
    console.print(f"[+] Targeting {len(all_subdomains)} potential subdomains.")

    # 5. Initialize Modules
    resolver = ResolverEngine()
    wildcard = WildcardDetector(resolver, args.domain, lax_mode=args.lax)
    prober = HTTPProber(limit=args.rate)
    port_scanner = PortScanner()
    injector = VulnScanner()
    
    # Specialist Modules
    takeover = TakeoverDetector()
    fuzzer = Fuzzer()
    fingerprinter = Fingerprinter()
    
    # Elite Modules
    js_analyzer = JSAnalyzer()

    # Omniscient Modules
    spider = OmniscientSpider(args.domain)
    mutator = SubdomainMutator(args.domain)

    # 6. Wildcard Detection
    console.print("[+] Detecting wildcards...")
    await wildcard.detect()

    # 7. Queue & Workers
    queue = asyncio.Queue()
    results = []
    seen_subdomains = set(all_subdomains)
    
    for sub in all_subdomains:
        queue.put_nowait(sub)

    # 8. Start Scan
    dashboard = ScanDashboard()
    dashboard.log(f"Starting scan on {args.domain}")
    
    scanned_count = 0
    
    def ui_update(event_type, data=None):
        nonlocal scanned_count
        if event_type == "scanned":
            scanned_count += 1
        elif event_type == "found":
            dashboard.add_result(data)
            dashboard.log(f"Found: {data['subdomain']}")

    workers = []
    
    with Live(dashboard.get_layout(), refresh_per_second=4, screen=True) as live:
        for _ in range(args.rate):
            # Pass all new modules to worker
            w = asyncio.create_task(worker(queue, resolver, wildcard, prober, port_scanner, injector, takeover, fuzzer, fingerprinter, js_analyzer, spider, mutator, results, seen_subdomains, args.probe, args.ports, args.inject, args.audit, args.elite, args.omni, ui_update))
            workers.append(w)
        
        while not queue.empty() or not all(w.done() for w in workers):
            dashboard.update_stats(scanned_count, args.rate)
            if queue.empty():
                
                break
            await asyncio.sleep(0.1)
        
        await queue.join()
        dashboard.update_stats(scanned_count, args.rate)
        dashboard.log("Scan Complete.")
        await asyncio.sleep(1)

    for w in workers:
        w.cancel()
    
    await prober.close()

    # Results handling
    export_results(results, args.output, format="json")
    if args.csv:
        export_results(results, args.output, format="csv")

    if not results and wildcard.is_wildcard and not args.lax:
         console.print("\n[bold red]![/bold red] [yellow]No results found, but Wildcard DNS was detected.[/yellow]")
         console.print("[yellow]Try running again with [bold white]--lax[/bold white] to bypass strict filtering.[/yellow]")
         console.print("[dim]Example: ./venv/bin/python3 main.py --domain ... --lax[/dim]\n")

    # 9. Interactive Post-Scan Menu
    await interactive_menu(results, ai_analyst, args)

if __name__ == "__main__":
    try:
        import uvloop
        uvloop.install()
    except ImportError:
        pass

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[!] Interrupted.")
    except Exception as e:
        console.print(f"[red]Fatal Error: {e}[/red]")
