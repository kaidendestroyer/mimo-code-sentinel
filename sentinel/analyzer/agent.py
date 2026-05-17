"""Analyzer Agent: contextual reasoning over Scanner findings."""

import re
from typing import Optional

from sentinel.config import SentinelConfig
from sentinel.models import (
    ScannerOutput, Finding, EnrichedFinding, AnalyzerOutput, Severity
)
from sentinel.analyzer.dataflow import DataFlowAnalyzer


class AnalyzerAgent:
    """Agent 2: Contextual analysis of scanner findings.
    
    Receives ScannerOutput JSON and performs contextual reasoning:
    - Traces data flow across files
    - Determines true vs false positives  
    - Assigns confidence scores and risk ratings
    - Generates attack scenarios
    
    Outputs AnalyzerOutput JSON for the Remediation agent.
    """

    def __init__(self, config: Optional[SentinelConfig] = None, base_path: str = "."):
        self.config = config or SentinelConfig()
        self.dataflow = DataFlowAnalyzer(base_path)

    def analyze(self, scanner_output: ScannerOutput) -> AnalyzerOutput:
        """Analyze all scanner findings for context."""
        enriched: list[EnrichedFinding] = []

        for finding in scanner_output.findings:
            enriched_finding = self._analyze_finding(finding)
            enriched.append(enriched_finding)

        true_pos = sum(1 for f in enriched if f.is_true_positive)
        false_pos = sum(1 for f in enriched if not f.is_true_positive)

        return AnalyzerOutput(
            enriched_findings=sorted(
                enriched,
                key=lambda f: (f.finding.severity.numeric, f.confidence_score),
                reverse=True,
            ),
            true_positives=true_pos,
            false_positives=false_pos,
        )

    def _analyze_finding(self, finding: Finding) -> EnrichedFinding:
        """Analyze a single finding with data-flow context."""
        # Extract variable name from the code snippet
        variable = self._extract_variable(finding)
        
        # Trace data flow
        trace = self.dataflow.trace_variable(
            variable, finding.file_path, finding.line_start
        )

        # Determine true/false positive
        is_tp, confidence, reasoning = self._classify(finding, trace)

        # Generate attack scenario
        attack_scenario = self._generate_attack_scenario(finding, trace)

        # Compute risk rating
        risk_rating = self._compute_risk(finding, confidence, trace)

        return EnrichedFinding(
            finding=finding,
            is_true_positive=is_tp,
            confidence_score=confidence,
            attack_scenario=attack_scenario,
            risk_rating=risk_rating,
            data_flow_trace=[
                f"{n.file_path}:{n.line} → {n.code}" for n in trace.nodes
            ],
            reasoning=reasoning,
        )

    def _extract_variable(self, finding: Finding) -> str:
        """Try to extract the suspicious variable name from code snippet."""
        snippet = finding.code_snippet.split("\n")
        target_line = snippet[len(snippet) // 2] if snippet else ""
        
        # Look for variable assignments or function args
        match = re.search(r"""(\w+)\s*=\s*""", target_line)
        if match:
            return match.group(1)
        
        # Look for function call arguments
        match = re.search(r"""\((\w+)""", target_line)
        if match:
            return match.group(1)
        
        return ""

    def _classify(
        self, finding: Finding, trace
    ) -> tuple[bool, float, str]:
        """Classify finding as true/false positive with confidence."""
        confidence = finding.confidence
        reasons = []

        # If data flow shows taint from source → sink
        if trace.is_tainted:
            confidence = min(confidence + 0.25, 0.95)
            reasons.append("Data flow shows user-controlled input reaching security sink")
        else:
            confidence = max(confidence - 0.15, 0.1)
            reasons.append("No clear data-flow path from user input found")

        # Sanitizers reduce confidence of true positive
        if trace.sanitizers_found:
            confidence = max(confidence - 0.2, 0.1)
            reasons.append(f"Sanitization detected: {trace.sanitizers_found[0][:60]}")

        # Severity-based adjustment
        if finding.severity == Severity.CRITICAL:
            confidence = min(confidence + 0.1, 0.95)
            reasons.append("Critical severity finding — elevated concern")
        elif finding.severity == Severity.LOW:
            confidence = max(confidence - 0.1, 0.1)

        # Threshold for classification
        is_tp = confidence >= 0.4
        
        return is_tp, round(confidence, 2), "; ".join(reasons)

    def _generate_attack_scenario(self, finding: Finding, trace) -> str:
        """Generate a human-readable attack scenario."""
        scenarios = {
            "CWE-89": "An attacker crafts malicious input that is interpolated into a SQL query, allowing data exfiltration or database modification.",
            "CWE-79": "An attacker injects JavaScript code that executes in victims' browsers, stealing session tokens or redirecting to phishing sites.",
            "CWE-78": "An attacker injects OS commands via unsanitized input, achieving remote code execution on the server.",
            "CWE-22": "An attacker uses path traversal sequences (../) to read arbitrary files outside the intended directory.",
            "CWE-502": "An attacker sends crafted serialized objects that, when deserialized, execute arbitrary code on the server.",
            "CWE-798": "Exposed credentials in source code can be extracted by anyone with repository access, leading to unauthorized API access.",
            "CWE-327": "Weak cryptographic algorithms can be broken with modern hardware, compromising encrypted data confidentiality.",
        }
        base = scenarios.get(finding.cwe, "Exploitation depends on the specific vulnerability context.")
        if trace.is_tainted:
            base += " Data flow analysis confirms user input reaches this code path."
        return base

    def _compute_risk(self, finding: Finding, confidence: float, trace) -> str:
        """Compute overall risk rating."""
        score = finding.severity.numeric * confidence
        if trace.is_tainted:
            score *= 1.2
        
        if score >= 3.0:
            return "critical"
        elif score >= 2.0:
            return "high"
        elif score >= 1.0:
            return "medium"
        else:
            return "low"
