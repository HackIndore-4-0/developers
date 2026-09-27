"""Evaluate custom security policies against Acunetix findings."""

from typing import List, Dict, Any


class AcunetixRuleEvaluator:
    def __init__(self, rules: List[Dict[str, Any]]):
        self.rules = rules

    def evaluate(self, finding: Dict[str, Any]) -> bool:
        for rule in self.rules:
            pattern = rule.get("pattern", "")
            if pattern and pattern in finding.get("name", "").lower():
                return True
        return False
