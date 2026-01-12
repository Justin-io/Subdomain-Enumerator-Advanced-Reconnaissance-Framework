import aiohttp
import asyncio
import logging

logger = logging.getLogger(__name__)

class TakeoverDetector:
    def __init__(self, timeout=5):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        # Signatures for common services
        self.signatures = {
            "Github": {"cname": "github.io", "fingerprint": "There is no app configured at this hostname"},
            "Heroku": {"cname": "herokuapp.com", "fingerprint": "No such app"},
            "AWS S3": {"cname": "s3.amazonaws.com", "fingerprint": "The specified bucket does not exist"},
            "Zendesk": {"cname": "zendesk.com", "fingerprint": "Help Center Closed"},
            "Shopify": {"cname": "myshopify.com", "fingerprint": "Sorry, this shop is currently unavailable"},
            "Tumblr": {"cname": "tumblr.com", "fingerprint": "Whatever you were looking for doesn't currently exist at this address"},
            "Ghost": {"cname": "ghost.io", "fingerprint": "The thing you were looking for is no longer here"},
            "Vercel": {"cname": "vercel.app", "fingerprint": "DEPLOYMENT_NOT_FOUND"}, # Vercel specific 404
            "Surge": {"cname": "surge.sh", "fingerprint": "project not found"},
            "Bitbucket": {"cname": "bitbucket.io", "fingerprint": "Repository not found"},
        }

    async def check(self, subdomain: str, cname: str, discovered_url: str = None) -> str:
        """
        Checks if the subdomain is vulnerable to takeover based on CNAME and HTTP response.
        Returns the name of the vulnerable service if found, else None.
        """
        if not cname:
            return None

        # 1. Match CNAME against signatures
        potential_service = None
        for service, data in self.signatures.items():
            if data["cname"] in cname:
                potential_service = service
                break
        
        if not potential_service:
            return None

        # 2. Verify with HTTP Probe
        # We need to fetch the page content to check for the fingerprint
        url = discovered_url
        if not url:
            url = f"http://{subdomain}" # Default to HTTP if no probe data

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    text = await resp.text()
                    fingerprint = self.signatures[potential_service]["fingerprint"]
                    
                    if fingerprint in text:
                        return f"takeover_possible_{potential_service}"
                        
        except Exception:
            pass # Probe failed, can't verify

        return None
