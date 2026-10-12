"""
Domain Matching Engine with Strict Label-Boundary Enforcement.
Guarantees that blocking 'example.com' matches 'example.com' and '*.example.com',
while NEVER falsely matching 'notexample.com' or 'example.company'.
"""

from typing import List, Optional, Set, Dict, Any

def get_domain_candidates(domain: str) -> List[str]:
    """
    Generates all parent domain candidates from most specific to TLD.
    e.g. 'sub.api.example.com' -> ['sub.api.example.com', 'api.example.com', 'example.com', 'com']
    """
    labels = domain.split(".")
    candidates = []
    for i in range(len(labels)):
        candidates.append(".".join(labels[i:]))
    return candidates

def is_label_boundary_match(query_domain: str, rule_domain: str, match_subdomains: bool = True) -> bool:
    """
    Evaluates whether query_domain matches rule_domain on strict label boundaries.
    Args:
        query_domain: The incoming normalized query domain (e.g. 'sub.example.com')
        rule_domain: The rule domain (e.g. 'example.com')
        match_subdomains: If True, matches query_domain == rule_domain OR *.rule_domain.
                          If False, matches only query_domain == rule_domain.
    """
    q = query_domain.lower().rstrip(".")
    r = rule_domain.lower().rstrip(".")
    
    if q == r:
        return True
    
    if match_subdomains:
        # Must end with dot + rule_domain to ensure label boundary separation
        if q.endswith("." + r):
            return True
            
    return False

class RuleIndex:
    """
    High-performance in-memory index for fast O(1) exact and O(labels) subdomain lookups.
    """
    def __init__(self):
        # Maps domain -> metadata dict
        self.exact_rules: Dict[str, Dict[str, Any]] = {}
        # Maps domain -> metadata dict (matches domain and all its subdomains)
        self.subdomain_rules: Dict[str, Dict[str, Any]] = {}

    def clear(self):
        self.exact_rules.clear()
        self.subdomain_rules.clear()

    def add_rule(self, domain: str, rule_type: str, metadata: Dict[str, Any]):
        domain = domain.lower().rstrip(".")
        if rule_type == "exact":
            self.exact_rules[domain] = metadata
        else:
            # default to subdomain matching
            self.subdomain_rules[domain] = metadata

    def match(self, domain: str) -> Optional[Dict[str, Any]]:
        domain = domain.lower().rstrip(".")
        
        # 1. Exact match has highest specificity
        if domain in self.exact_rules:
            res = dict(self.exact_rules[domain])
            res["matched_domain"] = domain
            res["match_type"] = "exact"
            return res

        # 2. Check subdomain candidates in order from most specific to root
        candidates = get_domain_candidates(domain)
        for cand in candidates:
            if cand in self.subdomain_rules:
                res = dict(self.subdomain_rules[cand])
                res["matched_domain"] = cand
                res["match_type"] = "subdomain"
                return res

        return None
