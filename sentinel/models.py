"""Data models for inter-agent communication."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import json


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def numeric(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    def __lt__(self, other):
        return self.numeric < other.numeric


@dataclass
class Finding:
    """A single security finding from the Scanner agent."""
    rule_id: str
    cwe: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    description: str
    confidence: float = 0.5
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class ScannerOutput:
    """Structured JSON output from Scanner → Analyzer handoff."""
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_ms: int = 0
    scanner_version: str = "0.1.0"

    def to_json(self) -> str:
        return json.dumps({
            "scanner_version": self.scanner_version,
            "files_scanned": self.files_scanned,
            "scan_duration_ms": self.scan_duration_ms,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }, indent=2)

    @classmethod
    def from_json(cls, data: str) -> "ScannerOutput":
        raw = json.loads(data)
        findings = [
            Finding(
                rule_id=f["rule_id"],
                cwe=f["cwe"],
                severity=Severity(f["severity"]),
                file_path=f["file_path"],
                line_start=f["line_start"],
                line_end=f["line_end"],
                code_snippet=f["code_snippet"],
                description=f["description"],
                confidence=f.get("confidence", 0.5),
                metadata=f.get("metadata", {}),
            )
            for f in raw.get("findings", [])
        ]
        return cls(
            findings=findings,
            files_scanned=raw.get("files_scanned", 0),
            scan_duration_ms=raw.get("scan_duration_ms", 0),
        )


@dataclass
class EnrichedFinding:
    """Analyzed finding from Analyzer → Remediation handoff."""
    finding: Finding
    is_true_positive: bool
    confidence_score: float
    attack_scenario: str
    risk_rating: str
    data_flow_trace: list[str] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            **self.finding.to_dict(),
            "is_true_positive": self.is_true_positive,
            "confidence_score": self.confidence_score,
            "attack_scenario": self.attack_scenario,
            "risk_rating": self.risk_rating,
            "data_flow_trace": self.data_flow_trace,
            "reasoning": self.reasoning,
        }


@dataclass
class AnalyzerOutput:
    """Structured JSON output from Analyzer → Remediation handoff."""
    enriched_findings: list[EnrichedFinding] = field(default_factory=list)
    true_positives: int = 0
    false_positives: int = 0

    def to_json(self) -> str:
        return json.dumps({
            "total_findings": len(self.enriched_findings),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "findings": [f.to_dict() for f in self.enriched_findings],
        }, indent=2)


@dataclass
class RemediationPatch:
    """A proposed fix for a vulnerability."""
    file_path: str
    original_code: str
    patched_code: str
    explanation: str
    prevention_notes: str
    diff: str = ""

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "original_code": self.original_code,
            "patched_code": self.patched_code,
            "explanation": self.explanation,
            "prevention_notes": self.prevention_notes,
            "diff": self.diff,
        }


@dataclass
class RemediationOutput:
    """Final output from Remediation agent."""
    patches: list[RemediationPatch] = field(default_factory=list)
    summary: str = ""

    def to_json(self) -> str:
        return json.dumps({
            "total_patches": len(self.patches),
            "summary": self.summary,
            "patches": [p.to_dict() for p in self.patches],
        }, indent=2)
