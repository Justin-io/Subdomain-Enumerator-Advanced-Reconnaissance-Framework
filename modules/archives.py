import aiohttp
import logging
import json

logger = logging.getLogger(__name__)

class ArchiveFetcher:
    def __init__(self, timeout=20):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.cdx_api = "http://web.archive.org/cdx/search/cdx"

    async def fetch_history(self, domain: str) -> list:
        """
        Queries the Wayback Machine for all historical URLs for the domain.
        Returns a list of unique URLs found.
        """
        urls = set()
        params = {
            "url": f"*.{domain}/*", # Wildcard search
            "output": "json",
            "fl": "original",
            "collapse": "urlkey"
        }
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(self.cdx_api, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # data[0] is header ["original"], rest are rows
                        if len(data) > 1:
                            for row in data[1:]:
                                urls.add(row[0])
        except Exception:
            pass
            
        return list(urls)
