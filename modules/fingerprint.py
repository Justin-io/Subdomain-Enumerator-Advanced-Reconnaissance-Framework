import aiohttp
import logging
from typing import Dict

logger = logging.getLogger(__name__)

class Fingerprinter:
    def __init__(self, timeout=5):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
    
    async def identify(self, url: str) -> Dict[str, str]:
        """
        Identifies technology stack based on HTTP headers and content.
        Returns a dict of detected technologies.
        """
        tech = {}
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    headers = resp.headers
                    
                    # 1. Header Analysis
                    if "Server" in headers:
                        tech["Server"] = headers["Server"]
                    if "X-Powered-By" in headers:
                        tech["PoweredBy"] = headers["X-Powered-By"]
                    if "X-Generator" in headers:
                        tech["Generator"] = headers["X-Generator"]
                        
                    # 2. Specific Cloud Providers
                    if "x-vercel-id" in headers:
                        tech["Cloud"] = "Vercel"
                    elif "cf-ray" in headers:
                        tech["Cloud"] = "Cloudflare"
                    elif "x-amz-request-id" in headers:
                        tech["Cloud"] = "AWS"
                    elif "X-GitHub-Request-Id" in headers:
                        tech["Cloud"] = "GitHub Pages"
                        
                    # 3. Content Analysis (Simple)
                    # text = await resp.text()
                    # if "wp-content" in text:
                    #     tech["CMS"] = "WordPress"
                    
        except Exception:
            pass # Probe failed
            
        return tech
