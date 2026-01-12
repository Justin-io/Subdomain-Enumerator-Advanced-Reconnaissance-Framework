import aiohttp
import asyncio
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class HTTPProber:
    def __init__(self, timeout: int = 5, limit: int = 100):
        # Limit concurrent connections for probing
        self.connector = aiohttp.TCPConnector(limit=limit, ssl=False)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.session = None

    async def get_session(self):
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(connector=self.connector, timeout=self.timeout)
        return self.session

    async def probe(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """
        Sends a HEAD request to the subdomain (http and https).
        Returns dict with status, server, etc. if successful.
        """
        session = await self.get_session()
        
        # We try HTTPS first, then HTTP
        protocols = ["https", "http"]
        
        for proto in protocols:
            url = f"{proto}://{subdomain}"
            try:
                async with session.head(url, allow_redirects=True) as response:
                    return {
                        "url": str(response.url),
                        "status_code": response.status,
                        "server": response.headers.get("Server", "Unknown"),
                        "title": "" # Not fetching body for HEAD, so no title
                    }
            except Exception:
                # If https fails, loop to http. If http fails, return None.
                continue
        
        return None

    async def close(self):
        if self.session:
            await self.session.close()
