import aiohttp
import asyncio
import logging
import dns.resolver
import dns.zone
import dns.exception
import dns.query

logger = logging.getLogger(__name__)

class PassiveRecon:
    def __init__(self, timeout=10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.crt_sh_url = "https://crt.sh"

    async def fetch_crt_sh(self, domain: str) -> set:
        """
        Queries crt.sh for subdomains found in SSL/TLS certificates.
        """
        subdomains = set()
        params = {
            "q": f"%.{domain}",
            "output": "json"
        }
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(self.crt_sh_url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            # Split multiple domains in one cert
                            names = name_value.split("\n")
                            for name in names:
                                name = name.strip()
                                # Clean up wildcards
                                if name.startswith("*."):
                                    name = name[2:]
                                if name.endswith(domain):
                                    subdomains.add(name)
        except Exception as e:
            logger.debug(f"CRT.sh query failed: {e}")
            
        return subdomains

    async def check_axfr(self, domain: str) -> set:
        """
        Attempts a DNS Zone Transfer (AXFR) against all nameservers.
        Results are returned as a set of subdomains.
        """
        found = set()
        try:
            # Get Nameservers
            # Run in executor because dnspython is blocking
            loop = asyncio.get_event_loop()
            
            def get_ns():
                try:
                    return dns.resolver.resolve(domain, 'NS')
                except:
                    return []
            
            ns_records = await loop.run_in_executor(None, get_ns)
            
            nameservers = [str(r.target) for r in ns_records]
            
            for ns in nameservers:
                def perform_axfr(ns_target):
                    try:
                        # Resolve NS IP
                        ns_ip = dns.resolver.resolve(ns_target, 'A')[0].to_text()
                        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5.0))
                        return [str(n) + "." + domain for n in zone.nodes.keys() if str(n) != "@"]
                    except:
                        return []

                # Run AXFR in executor
                zone_subdomains = await loop.run_in_executor(None, perform_axfr, ns)
                if zone_subdomains:
                    logger.warning(f"AXFR SUCCESSFUL on {ns} for {domain}!")
                    for s in zone_subdomains:
                        found.add(s)
                        
        except Exception as e:
            logger.debug(f"AXFR check failed: {e}")
            
        return found
