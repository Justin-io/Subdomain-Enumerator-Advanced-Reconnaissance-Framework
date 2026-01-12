import aiohttp
import asyncio
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

class VulnScanner:
    def __init__(self, timeout=5):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.payloads = {
            "xss": ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
            "sqli": ["' OR 1=1 --", "' UNION SELECT 1,2,3 --"],
            "lfi": ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
            "open_redirect": ["//google.com", "https://google.com"]
        }

    async def scan(self, url: str) -> list:
        """
        Scans a given URL for simple vulnerabilities by fuzzing query parameters.
        Returns a list of detected vulnerability strings.
        """
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # No parameters to inject, skip param-based injection
            # But we could check headers or paths (future)
            return []

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            # Test XSS
            for p in self.payloads["xss"]:
                if await self._check_reflection(session, url, params, p):
                    findings.append(f"Potential XSS (Reflected): {p}")
                    break # Stop after one XSS find per URL to reduce noise

            # Test SQLi (Error Based - Simple Check)
            for p in self.payloads["sqli"]:
                if await self._check_error(session, url, params, p):
                    findings.append(f"Potential SQLi (Error): {p}")
                    break

            # Test Open Redirect (if param looks like a url)
            redirect_params = [k for k in params.keys() if "url" in k or "next" in k or "dest" in k]
            for rp in redirect_params:
                for p in self.payloads["open_redirect"]:
                     if await self._check_redirect(session, url, params, rp, p):
                         findings.append(f"Open Redirect: {p}")
                         break

        if findings:
            logger.warning(f"VULNERABILITIES FOUND on {url}: {findings}")
            
        return findings

    async def _check_reflection(self, session, base_url, params, payload):
        # Inject payload into all params
        new_params = params.copy()
        for k in new_params:
            new_params[k] = payload
        
        target_url = self._build_url(base_url, new_params)
        
        try:
            async with session.get(target_url) as resp:
                text = await resp.text()
                if payload in text:
                    return True
        except:
            pass
        return False

    async def _check_error(self, session, base_url, params, payload):
        new_params = params.copy()
        # Inject into first param for now
        first_key = list(new_params.keys())[0]
        new_params[first_key] = [new_params[first_key][0] + payload]
        
        target_url = self._build_url(base_url, new_params)
        
        sql_errors = ["mysql_fetch_array", "syntax error", "ORA-", "SQLServer"]
        try:
            async with session.get(target_url) as resp:
                text = await resp.text()
                for err in sql_errors:
                    if err.lower() in text.lower():
                        return True
        except:
            pass
        return False

    async def _check_redirect(self, session, base_url, params, param_key, payload):
        new_params = params.copy()
        new_params[param_key] = payload
        target_url = self._build_url(base_url, new_params)
        
        try:
            async with session.get(target_url, allow_redirects=False) as resp:
                if resp.status in [301, 302, 307, 308]:
                    location = resp.headers.get("Location", "")
                    if payload in location or "google.com" in location:
                        return True
        except:
            pass
        return False

    def _build_url(self, base_url, new_params):
        parsed = urlparse(base_url)
        query = urlencode(new_params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
