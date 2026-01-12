import os
from typing import Set, Generator

class WordlistGenerator:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.permutations_map = {
            "api": ["api-dev", "api-staging", "v1-api", "v2-api"],
            "dev": ["dev-api", "dev-server", "backend-dev"],
            "staging": ["staging-api", "staging-db"],
            "test": ["test-env", "uat"],
        }

    def load(self) -> Set[str]:
        """Loads the wordlist from a file into a set."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Wordlist not found: {self.filepath}")
        
        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
            words = {line.strip() for line in f if line.strip()}
        
        return words

    def generate_permutations(self, subdomains: Set[str]) -> Set[str]:
        """
        Generates simple permutations for known interesting subdomains.
        For an MVP, this just adds variations if specific keywords are found.
        """
        extra = set()
        for sub in subdomains:
            # Check basic permutation rules
            for keyword, variants in self.permutations_map.items():
                if keyword in sub:
                    for v in variants:
                        # minimal logic: replace 'keyword' with 'variant' 
                        # or just add 'variant' if it's a root substitution
                        # For now, let's just append permutations as completely new subdomains
                        # to be safe, assuming the wordlist contained just the prefix.
                        
                        # Case 1: sub is exactly key, e.g. "api" -> "api-dev"
                        if sub == keyword:
                            extra.update(variants)
                        
                        # Case 2: sub starts/ends with key? (TODO: refine for complex logic)
        
        return extra
