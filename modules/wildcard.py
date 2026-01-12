import uuid
import logging
from typing import Set, List
from .dns_resolver import ResolverEngine

logger = logging.getLogger(__name__)

class WildcardDetector:
    def __init__(self, resolver: ResolverEngine, domain: str, lax_mode: bool = False):
        self.resolver = resolver
        self.domain = domain
        self.wildcard_ips: Set[str] = set()
        self.is_wildcard = False
        self.lax_mode = lax_mode

    async def detect(self, checks: int = 3) -> bool:
        """
        Detects if the domain has wildcard DNS enabled.
        Resolves random subdomains and checks if they return IPs.
        """
        logger.info(f"Checking for wildcard DNS on *.{self.domain}...")
        
        detected_ips = set()
        
        for _ in range(checks):
            # Generate a random subdomain that definitely shouldn't exist
            rand_sub = f"{uuid.uuid4().hex[:16]}.{self.domain}"
            
            # Allow for A and CNAME check? Just A for now to get IP.
            # aiodns query returns a list of objects for 'A' records
            result = await self.resolver.resolve(rand_sub, 'A')
            
            if result:
                for a_rec in result:
                    detected_ips.add(a_rec.host)

        if detected_ips:
            if self.lax_mode:
                logger.warning(f"Wildcard DNS detected but --lax mode is ON. Accepting all IPs.")
                self.is_wildcard = False # Disable filtering effectively
                return False
            else:
                self.is_wildcard = True
                self.wildcard_ips = detected_ips
                logger.warning(f"Wildcard DNS detected! Ignoring IPs: {self.wildcard_ips}")
                return True
        
        logger.info("No wildcard DNS detected.")
        return False

    def is_false_positive(self, ip_addresses: List[str]) -> bool:
        """
        Checks if the resolved IPs match known wildcard IPs.
        """
        if not self.is_wildcard:
            return False
            
        # If any of the resolved IPs are in the wildcard set, treat as FP
        # (This might be too aggressive if a legit sub shares IP with wildcard, 
        # but standard for this type of tool. --lax disables this.)
        msg_match = False
        for ip in ip_addresses:
            if ip in self.wildcard_ips:
                msg_match = True
                break
        
        if msg_match:
            # If all IPs match the wildcard, it's a false positive.
            # If at least one IP is DIFFERENT, maybe it's valid?
            # For now, strict: if ANY IP matches wildcard, reject. (Safest for noise reduction)
            # Actually, if we have [ValidIP, WildcardIP] (unlikely for DNS round robin?)
            # Let's keep it strict for now.
            return True
            
        return False
