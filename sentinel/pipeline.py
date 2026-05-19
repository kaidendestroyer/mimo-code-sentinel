"""Pipeline orchestrator: chains Scanner → Analyzer → Remediation."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.config import SentinelConfig
from sentinel.models import (
    ScannerOutput,
    AnalyzerOutput,
    RemediationOutput,
)
from sentinel.scanner.agent import ScannerAgent
from sentinel.analyzer.agent import AnalyzerAgent
from sentinel.remediation.agent import RemediationAgent


@dataclass
class PipelineResult:
    """Full pipeline result with timing for each stage."""
    scanner_output: ScannerOutput
    analyzer_output: AnalyzerOutput
    remediation_output: RemediationOutput
    timings: dict[str, float] = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.scanner_output.findings)

    @property
    def true_positives(self) -> int:
        return self.analyzer_output.true_positives

    @property
    def patches_generated(self) -> int:
        return len(self.remediation_output.patches)

    def to_json(self) -> str:
        return json.dumps({
            "timings_ms": self.timings,
            "summary": {
                "files_scanned": self.scanner_output.files_scanned,
                "total_findings": self.total_findings,
                "true_positives": self.true_positives,
                "false_positives": self.analyzer_output.false_positives,
                "patches_generated": self.patches_generated,
            },
            "scanner": json.loads(self.scanner_output.to_json()),
            "analyzer": json.loads(self.analyzer_output.to_json()),
            "remediation": json.loads(self.remediation_output.to_json()),
        }, indent=2)


class Pipeline:
    """Orchestrates the 3-agent security scanning pipeline.

    Usage:
        pipeline = Pipeline(config)
        result = pipeline.run("./my-project")
        print(result.to_json())
    """

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()

    def run(self, target_path: str) -> PipelineResult:
        """Run the full Scanner → Analyzer → Remediation pipeline."""
        timings: dict[str, float] = {}

        # Stage 1: Scanner
        t0 = time.monotonic()
        scanner = ScannerAgent(self.config)
        scanner_output = scanner.scan_directory(target_path)
        timings["scanner_ms"] = (time.monotonic() - t0) * 1000

        if not scanner_output.findings:
            return PipelineResult(
                scanner_output=scanner_output,
                analyzer_output=AnalyzerOutput(),
                remediation_output=RemediationOutput(),
                timings=timings,
            )

        # Stage 2: Analyzer
        t0 = time.monotonic()
        analyzer = AnalyzerAgent(self.config, base_path=target_path)
        analyzer_output = analyzer.analyze(scanner_output)
        timings["analyzer_ms"] = (time.monotonic() - t0) * 1000

        # Stage 3: Remediation
        t0 = time.monotonic()
        remediator = RemediationAgent(self.config)
        remediation_output = remediator.remediate(analyzer_output)
        timings["remediation_ms"] = (time.monotonic() - t0) * 1000

        return PipelineResult(
            scanner_output=scanner_output,
            analyzer_output=analyzer_output,
            remediation_output=remediation_output,
            timings=timings,
        )
