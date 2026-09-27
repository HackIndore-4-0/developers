"""Generate actionable patch guidelines and WAF rules."""

from typing import Dict, Any


def generate_mitigation_plan(finding_name: str, cwe_id: int) -> Dict[str, str]:
    """Provide code-level mitigation and WAF regex rule for common web bugs."""
    if cwe_id == 89:  # SQLi
        return {
            "code_fix": "Use parameterized queries or ORM prepared statements.",
            "waf_rule": "SecRule ARGS "(?i)(union\s+select|insert\s+into)" "id:1001,deny,status:403"",
        }
    if cwe_id == 79:  # XSS
        return {
            "code_fix": "Context-aware output encoding and apply Content-Security-Policy header.",
            "waf_rule": "SecRule ARGS "(?i)(<script|javascript:|onerror=)" "id:1002,deny,status:403"",
        }
    return {
        "code_fix": "Validate and strictly sanitize input against allowlist schema.",
        "waf_rule": "SecRule REQUEST_URI "\.\./" "id:1003,deny,status:403"",
    }
