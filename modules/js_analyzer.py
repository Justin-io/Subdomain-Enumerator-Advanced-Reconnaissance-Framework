import aiohttp
import re
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class JSAnalyzer:
    def __init__(self, timeout=10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.patterns = {
            "AWS API Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
            "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Facebook Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
            "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
            "Generic Secret": r"(?i)(api_key|access_token|secret_key)[\s:=]+['\"]([a-zA-Z0-9-_]{16,})['\"]"
        }

    async def analyze(self, url: str) -> list:
        """
        Fetches the page, finds JS files, and scans them for secrets.
        Returns a list of findings string.
        """
        findings = []
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # 1. Fetch Main Page
                async with session.get(url) as resp:
                    html = await resp.text()

                # 2. Extract Script Srcs
                # Simple regex for finding src="..."
                scripts = re.findall(r'<script[^>]+src=["\'](.*?)["\']', html)
                
                # Deduplicate and normalize URLs
                script_urls = set()
                for s in scripts:
                    full_url = urljoin(url, s)
                    script_urls.add(full_url)
                
                # 3. Analyze Each Script
                for script_url in script_urls:
                    try:
                        async with session.get(script_url) as script_resp:
                            if script_resp.status == 200:
                                js_content = await script_resp.text()
                                results = self._scan_content(js_content)
                                if results:
                                    for r in results:
                                        findings.append(f"In {script_url}: {r}")
                    except Exception:
                        pass
                        
        except Exception:
            pass # Main page fetch failed

        return findings

    def _scan_content(self, content: str) -> list:
        found = []
        for name, pattern in self.patterns.items():
            matches = re.finditer(pattern, content)
            for m in matches:
                # Truncate secret for log safety if needed, but for recon we show it
                secret = m.group(0)
                found.append(f"{name} Found: {secret[:10]}...")
        return found
