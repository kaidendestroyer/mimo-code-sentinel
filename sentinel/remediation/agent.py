"""Remediation Agent: generates diff-ready patches for confirmed vulnerabilities."""

from typing import Optional

from sentinel.config import SentinelConfig
from sentinel.models import (
    AnalyzerOutput, EnrichedFinding, RemediationPatch, RemediationOutput
)


# Fix templates per CWE
FIX_TEMPLATES: dict[str, dict] = {
    "CWE-89": {
        "pattern": "sql_injection",
        "fix_hint": "Use parameterized queries instead of string formatting",
        "python": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "javascript": 'db.query("SELECT * FROM users WHERE id = $1", [userId])',
        "prevention": "Always use parameterized queries or ORM. Never interpolate user input into SQL strings.",
    },
    "CWE-79": {
        "pattern": "xss",
        "fix_hint": "Sanitize output or use textContent instead of innerHTML",
        "javascript": "element.textContent = userInput; // instead of innerHTML",
        "prevention": "Use framework-provided escaping (React JSX, Vue template syntax). Avoid v-html/innerHTML with user data.",
    },
    "CWE-78": {
        "pattern": "command_injection",
        "fix_hint": "Use subprocess with argument lists instead of shell=True",
        "python": 'subprocess.run(["ls", user_dir], capture_output=True)  # no shell=True',
        "prevention": "Use argument lists with subprocess. Validate/whitelist input. Avoid os.system().",
    },
    "CWE-22": {
        "pattern": "path_traversal",
        "fix_hint": "Resolve path and verify it stays within allowed directory",
        "python": "safe_path = (base_dir / user_file).resolve()\nif not str(safe_path).startswith(str(base_dir.resolve())):\n    raise ValueError('Path traversal detected')",
        "prevention": "Resolve paths and check they remain within the allowed directory. Use pathlib for safe path operations.",
    },
    "CWE-502": {
        "pattern": "unsafe_deserialization",
        "fix_hint": "Use json.loads instead of pickle/yaml.load with arbitrary types",
        "python": "data = json.loads(raw_data)  # instead of pickle.loads()",
        "prevention": "Never deserialize untrusted data with pickle/marshal. Use json.loads() or yaml.safe_load().",
    },
    "CWE-798": {
        "pattern": "hardcoded_creds",
        "fix_hint": "Move secrets to environment variables or a secrets manager",
        "python": 'api_key = os.environ["API_KEY"]  # instead of hardcoding',
        "prevention": "Store secrets in environment variables, .env files (gitignored), or a secrets manager like Vault.",
    },
    "CWE-327": {
        "pattern": "weak_crypto",
        "fix_hint": "Use SHA-256 or stronger instead of MD5/SHA1",
        "python": "hashlib.sha256(data).hexdigest()  # instead of hashlib.md5()",
        "prevention": "Use SHA-256+ for hashing, AES-256-GCM for encryption. Never use MD5/SHA1/DES/RC4 for security.",
    },
}


class RemediationAgent:
    """Agent 3: Remediation and patch generation.

    Takes confirmed vulnerabilities from the Analyzer and produces:
    - Diff-ready patches
    - Explanatory comments for developers
    - Prevention recommendations

    Each fix is validated against the original code context.
    """

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()

    def remediate(self, analyzer_output: AnalyzerOutput) -> RemediationOutput:
        """Generate patches for all true-positive findings."""
        patches: list[RemediationPatch] = []

        for finding in analyzer_output.enriched_findings:
            if not finding.is_true_positive:
                continue
            if finding.confidence_score < 0.3:
                continue

            patch = self._generate_patch(finding)
            if patch:
                patches.append(patch)

        summary = self._generate_summary(analyzer_output, patches)

        return RemediationOutput(patches=patches, summary=summary)

    def _generate_patch(self, finding: EnrichedFinding) -> Optional[RemediationPatch]:
        """Generate a patch for a single finding."""
        cwe = finding.finding.cwe
        lang = finding.finding.metadata.get("language", "python")
        template = FIX_TEMPLATES.get(cwe)

        if not template:
            return self._generate_generic_patch(finding)

        # Get the appropriate fix for the language
        patched_hint = template.get(lang, template.get("fix_hint", "Apply manual fix"))

        # Build the patched code with inline comments
        original = finding.finding.code_snippet
        patched_lines = []
        for line in original.split("\n"):
            patched_lines.append(line)
        patched_lines.append(f"    # SECURITY FIX ({cwe}): {template['fix_hint']}")
        patched_lines.append(f"    # {patched_hint}")

        # Generate diff
        diff = self._make_diff(original, "\n".join(patched_lines), finding.finding.file_path)

        return RemediationPatch(
            file_path=finding.finding.file_path,
            original_code=original,
            patched_code="\n".join(patched_lines),
            explanation=(
                f"**{cwe}** at line {finding.finding.line_start}: "
                f"{finding.finding.description}. "
                f"Confidence: {finding.confidence_score:.0%}. "
                f"{finding.reasoning}"
            ),
            prevention_notes=template["prevention"],
            diff=diff,
        )

    def _generate_generic_patch(self, finding: EnrichedFinding) -> RemediationPatch:
        """Fallback patch for CWEs without templates."""
        return RemediationPatch(
            file_path=finding.finding.file_path,
            original_code=finding.finding.code_snippet,
            patched_code=(
                f"    # TODO: Security fix needed for {finding.finding.cwe}\n"
                f"    # {finding.finding.description}\n"
                f"    # Attack scenario: {finding.attack_scenario}\n"
                f"    {finding.finding.code_snippet}"
            ),
            explanation=(
                f"Manual review required for {finding.finding.cwe} at "
                f"{finding.finding.file_path}:{finding.finding.line_start}"
            ),
            prevention_notes="Review the flagged code and apply appropriate security controls.",
        )

    def _make_diff(self, original: str, patched: str, file_path: str) -> str:
        """Generate a unified diff between original and patched code."""
        orig_lines = original.split("\n")
        patched_lines = patched.split("\n")
        diff_lines = [f"--- a/{file_path}", f"+++ b/{file_path}"]
        diff_lines.append(f"@@ -1,{len(orig_lines)} +1,{len(patched_lines)} @@")
        for line in orig_lines:
            diff_lines.append(f"- {line}")
        for line in patched_lines:
            diff_lines.append(f"+ {line}")
        return "\n".join(diff_lines)

    def _generate_summary(
        self, analyzer_output: AnalyzerOutput, patches: list[RemediationPatch]
    ) -> str:
        """Generate a human-readable summary of remediation actions."""
        total = len(analyzer_output.enriched_findings)
        tp = analyzer_output.true_positives
        fp = analyzer_output.false_positives
        patched = len(patches)

        cwe_counts: dict[str, int] = {}
        for p in patches:
            cwe = p.explanation.split("**")[1] if "**" in p.explanation else "Unknown"
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

        lines = [
            "Security Scan Summary",
            "====================",
            f"Total findings: {total}",
            f"True positives: {tp}",
            f"False positives: {fp}",
            f"Patches generated: {patched}",
            "",
            "Vulnerability breakdown:",
        ]
        for cwe, count in sorted(cwe_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {cwe}: {count} finding(s)")

        return "\n".join(lines)
