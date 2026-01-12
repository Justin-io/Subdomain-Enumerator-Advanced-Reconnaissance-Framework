import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class OmniscientSpider:
    def __init__(self, root_domain):
        self.root_domain = root_domain
        # Regex to find subdomains of the root domain in text
        # Specifically looks for strings like 'sub.root.com' or '//sub.root.com'
        self.subdomain_pattern = re.compile(
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + 
            re.escape(self.root_domain)
        )

    def extract_subdomains(self, html_content: str) -> set:
        """
        Parses HTML content to find any mentions of subdomains of the root.
        This includes hrefs, srcs, and plain text.
        """
        found = set()
        
        # 1. Broad Regex Match
        matches = self.subdomain_pattern.findall(html_content)
        for match in matches:
            sub = match.lower().strip()
            if sub.endswith(self.root_domain):
                found.add(sub)
                
        # 2. Extract from standard attributes just in case regex missed some weird formatting
        # (Though the regex above is quite broad)
        
        return found
