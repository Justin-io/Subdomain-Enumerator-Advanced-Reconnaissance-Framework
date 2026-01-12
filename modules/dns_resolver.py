import asyncio
import aiodns
import random
import logging
from typing import List, Optional, Any

logger = logging.getLogger(__name__)

# List of trusted public resolvers
PUBLIC_RESOLVERS = [
    "8.8.8.8", "8.8.4.4",        # Google
    "1.1.1.1", "1.0.0.1",        # Cloudflare
    "9.9.9.9", "149.112.112.112", # Quad9
    "208.67.222.222", "208.67.220.220" # OpenDNS
]

class ResolverEngine:
    def __init__(self, nameservers: List[str] = None, loop: asyncio.AbstractEventLoop = None):
        self.loop = loop or asyncio.get_event_loop()
        self.nameservers = nameservers or PUBLIC_RESOLVERS
        
        # Initialize aiodns resolver
        # we can't easily rotate per request with a single instance effectively 
        # unless we re-init or rely on c-ares behavior. 
        # For high perf, let's trust c-ares to handle the list we give it.
        self.resolver = aiodns.DNSResolver(loop=self.loop, nameservers=self.nameservers)
    
    async def resolve(self, hostname: str, record_type: str = 'A') -> Optional[Any]:
        """
        Resolves a hostname for a specific record type.
        Returns the result object or None if retrieval failed (NXDOMAIN/Timeout).
        """
        try:
            return await self.resolver.query(hostname, record_type)
        except aiodns.error.DNSError as e:
            # Code 4 is NOT_FOUND (NXDOMAIN), Code 12 is TIMEOUT
            if e.args[0] == 4: # NXDOMAIN
                return None
            elif e.args[0] == 12: # Timeout
                # We could log debug here, but usually it just means the query failed
                return None
            elif e.args[0] == 1: # NODATA (exists but no A record)
                return None
            else:
                # Other errors
                # logger.debug(f"DNS Error for {hostname}: {e}")
                return None
        except Exception as e:
            logger.debug(f"Unexpected error resolving {hostname}: {e}")
            return None
