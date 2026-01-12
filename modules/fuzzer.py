import aiohttp
import asyncio
import logging

logger = logging.getLogger(__name__)

class Fuzzer:
    def __init__(self, timeout=5):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.paths = [
            ".env",
            ".git/HEAD",
            ".svn/entries",
            ".ds_store",
            "config.php",
            "wp-config.php.bak",
            "backup.zip",
            "dump.sql",
            "server-status",
            "phpinfo.php",
            "Dockerfile",
            "docker-compose.yml"
        ]

    async def fuzz(self, url: str) -> list:
        """
        Fuzzes the URL for sensitive files.
        Returns a list of discovered paths.
        """
        findings = []
        base_url = url.rstrip("/")
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for path in self.paths:
                target = f"{base_url}/{path}"
                try:
                    async with session.get(target, allow_redirects=False) as resp:
                        if resp.status == 200:
                             # Basic False Positive check (if response is empty or generic html)
                             content_len = resp.content_length
                             if content_len and content_len > 0:
                                 # We could add more specific checks (e.g., look for "DB_PASSWORD" in .env)
                                 findings.append(f"Exposed File: {path}")
                except:
                    pass
        
        return findings
