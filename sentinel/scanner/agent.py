"""Scanner Agent: performs static analysis across a codebase."""

import os
import time
from pathlib import Path
from typing import Optional

from sentinel.config import SentinelConfig
from sentinel.models import Finding, ScannerOutput, Severity
from sentinel.scanner.rules import ScanRule, BUILTIN_RULES, get_rules_for_language


# File extension → language mapping
EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".vue": "vue",
    ".html": "html",
}


class ScannerAgent:
    """Agent 1: Static analysis scanner.
    
    Performs regex and AST-based pattern matching to identify
    suspicious security patterns. Outputs structured JSON for
    the Analyzer agent.
    """

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()
        self.rules = BUILTIN_RULES

    def scan_directory(self, target_path: str) -> ScannerOutput:
        """Scan all files in a directory tree."""
        start = time.monotonic()
        target = Path(target_path)
        findings: list[Finding] = []
        files_scanned = 0

        for file_path in self._iter_source_files(target):
            file_findings = self._scan_file(file_path, target)
            findings.extend(file_findings)
            files_scanned += 1

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return ScannerOutput(
            findings=sorted(findings, key=lambda f: f.severity, reverse=True),
            files_scanned=files_scanned,
            scan_duration_ms=elapsed_ms,
        )

    def _iter_source_files(self, root: Path):
        """Yield source files, respecting exclude patterns."""
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            # Skip excluded directories
            dirnames[:] = [
                d for d in dirnames
                if not self._is_excluded(os.path.join(rel_dir, d))
            ]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.suffix in EXTENSION_MAP and not self._is_excluded(
                    os.path.join(rel_dir, fname)
                ):
                    if fpath.stat().st_size <= self.config.max_file_size_kb * 1024:
                        yield fpath

    def _is_excluded(self, rel_path: str) -> bool:
        """Check if path matches any exclude pattern."""
        from fnmatch import fnmatch
        return any(fnmatch(rel_path, pat) for pat in self.config.exclude_patterns)

    def _scan_file(self, file_path: Path, root: Path) -> list[Finding]:
        """Scan a single file for vulnerability patterns."""
        rel_path = str(file_path.relative_to(root))
        language = EXTENSION_MAP.get(file_path.suffix, "unknown")
        applicable_rules = get_rules_for_language(language)

        try:
            content = file_path.read_text(errors="replace")
        except (OSError, PermissionError):
            return []

        findings = []
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            for rule in applicable_rules:
                if rule.matches(line):
                    # Get context (2 lines before and after)
                    ctx_start = max(0, i - 3)
                    ctx_end = min(len(lines), i + 2)
                    snippet = "\n".join(lines[ctx_start:ctx_end])

                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        cwe=rule.cwe,
                        severity=Severity(rule.severity),
                        file_path=rel_path,
                        line_start=i,
                        line_end=i,
                        code_snippet=snippet,
                        description=rule.description,
                        confidence=0.6,  # Base confidence for regex match
                        metadata={"language": language},
                    ))
        return findings
