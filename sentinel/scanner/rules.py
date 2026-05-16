"""Security scanning rules and pattern definitions."""

import re
from dataclasses import dataclass
from typing import Callable


@dataclass
class ScanRule:
    """A single scanning rule."""
    rule_id: str
    cwe: str
    pattern: re.Pattern
    severity: str
    description: str
    languages: list[str] = None  # None = all languages

    def matches(self, line: str) -> bool:
        return bool(self.pattern.search(line))


# Built-in rules for common vulnerability patterns
BUILTIN_RULES: list[ScanRule] = [
    # SQL Injection
    ScanRule(
        rule_id="SQL-001",
        cwe="CWE-89",
        pattern=re.compile(
            r"""(?:execute|cursor\.execute|query|raw)\s*\(\s*["'].*(?:%s|%d|\{|\+)""",
            re.IGNORECASE,
        ),
        severity="high",
        description="Potential SQL injection via string formatting in query",
        languages=["python"],
    ),
    ScanRule(
        rule_id="SQL-002",
        cwe="CWE-89",
        pattern=re.compile(
            r"""(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+(?:\s*\w+|\s*["'])""",
            re.IGNORECASE,
        ),
        severity="high",
        description="Potential SQL injection via string concatenation",
        languages=["javascript", "java", "php"],
    ),
    # Hardcoded secrets
    ScanRule(
        rule_id="SEC-001",
        cwe="CWE-798",
        pattern=re.compile(
            r"""(?:password|secret|api_key|apikey|token|private_key)\s*=\s*["'][^"']{8,}["']""",
            re.IGNORECASE,
        ),
        severity="critical",
        description="Hardcoded credential or secret detected",
    ),
    ScanRule(
        rule_id="SEC-002",
        cwe="CWE-798",
        pattern=re.compile(
            r"""(?:AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36})""",
        ),
        severity="critical",
        description="Exposed API key pattern (AWS/OpenAI/GitHub)",
    ),
    # Command Injection
    ScanRule(
        rule_id="CMD-001",
        cwe="CWE-78",
        pattern=re.compile(
            r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.run)\s*\(.*(?:%s|\+|f["']|\.\s*format)""",
        ),
        severity="high",
        description="Potential command injection via unsanitized input",
        languages=["python"],
    ),
    # Path Traversal
    ScanRule(
        rule_id="PATH-001",
        cwe="CWE-22",
        pattern=re.compile(
            r"""(?:open|send_file|send_from_directory)\s*\(.*(?:request\.|input\(|argv|\+)""",
        ),
        severity="high",
        description="Potential path traversal from user-controlled input",
    ),
    # Unsafe Deserialization
    ScanRule(
        rule_id="DESER-001",
        cwe="CWE-502",
        pattern=re.compile(
            r"""(?:pickle\.loads|yaml\.load|marshal\.loads|jsonpickle\.decode)\s*\(""",
        ),
        severity="critical",
        description="Unsafe deserialization detected",
        languages=["python"],
    ),
    # XSS
    ScanRule(
        rule_id="XSS-001",
        cwe="CWE-79",
        pattern=re.compile(
            r"""(?:innerHTML|outerHTML|document\.write|v-html)\s*[=]""",
        ),
        severity="medium",
        description="Potential XSS via unsafe DOM manipulation",
        languages=["javascript", "typescript", "vue"],
    ),
    # Insecure crypto
    ScanRule(
        rule_id="CRYPTO-001",
        cwe="CWE-327",
        pattern=re.compile(
            r"""(?:MD5|SHA1|DES|RC4|ECB)""",
        ),
        severity="medium",
        description="Weak or deprecated cryptographic algorithm",
    ),
]


def get_rules_for_language(language: str) -> list[ScanRule]:
    """Get applicable rules for a given programming language."""
    return [
        r for r in BUILTIN_RULES
        if r.languages is None or language.lower() in r.languages
    ]
