import logging

logger = logging.getLogger(__name__)

class SubdomainMutator:
    def __init__(self, root_domain):
        self.root_domain = root_domain
        self.prefixes = ["dev-", "staging-", "api-", "internal-", "test-", "v1-", "v2-", "beta-", "prod-", "old-"]
        self.suffixes = ["-v1", "-v2", "-test", "-beta", "-prod", "-old", "-internal", "-staging", "-dev"]
        self.common_words = ["admin", "portal", "vpn", "mail", "dev", "staging", "api", "test", "cdn", "db", "mysql", "git", "web", "static"]

    def mutate(self, subdomain: str) -> set:
        """
        Generates smart permutations for a discovered subdomain.
        """
        mutations = set()
        
        # 1. Strip root domain to get naming parts
        prefix_part = subdomain.replace(f".{self.root_domain}", "")
        
        # 2. Basic Prefix/Suffix additions
        for p in self.prefixes:
            mutations.add(f"{p}{prefix_part}.{self.root_domain}")
            
        for s in self.suffixes:
            mutations.add(f"{prefix_part}{s}.{self.root_domain}")
            
        # 3. Part-based mutation (e.g. dev.api -> staging.api)
        parts = prefix_part.split(".")
        if len(parts) > 1:
            for i, part in enumerate(parts):
                    mutations.add(f"{'.'.join(new_parts)}.{self.root_domain}")
        
        # 4. Number mutations (e.g. api1 -> api2)
        import re
        if re.search(r'\d+$', prefix_part):
            base = re.sub(r'\d+$', '', prefix_part)
            for i in range(1, 4): # Try common versions
                mutations.add(f"{base}{i}.{self.root_domain}")
        else:
             mutations.add(f"{prefix_part}1.{self.root_domain}")

        # Final cleanup: deduplicate and remove self
        if subdomain in mutations:
            mutations.remove(subdomain)
            
        return mutations

    def generate_wildcard_variations(self, wordlist: list) -> set:
        """
        Can be used to generate a massive list of permutations from a wordlist.
        For --omni, we usually mutate on-the-fly.
        """
        pass
