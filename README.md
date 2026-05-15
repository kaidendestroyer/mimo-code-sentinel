# mimo-code-sentinel

Multi-agent code security scanner built with MiMo AI. Uses a 3-agent sequential pipeline to scan, analyze, and remediate security vulnerabilities in codebases.

## Architecture

```
┌─────────────┐     JSON      ┌──────────────┐     JSON      ┌─────────────────┐
│   Scanner   │──────────────▶│   Analyzer   │──────────────▶│  Remediation    │
│   Agent     │               │   Agent      │               │  Agent          │
└─────────────┘               └──────────────┘               └─────────────────┘
  AST parsing                   Context-aware                  Diff-ready patches
  Pattern matching              Data-flow tracing              Prevention advice
  CWE classification            Confidence scoring             Context validation
```

### Agent 1: Scanner
Performs static analysis using AST parsing and regex patterns. Identifies suspicious patterns (SQL injection, hardcoded secrets, unsafe deserialization, path traversal) and outputs structured JSON with file locations, line numbers, severity scores, and CWE classifications.

### Agent 2: Analyzer
Receives Scanner output and performs contextual reasoning. Traces data flow across files to determine true/false positives. Evaluates: Is user input reaching this sink unsanitized? Is this secret used in production code paths? Outputs enriched findings with confidence scores, attack scenarios, and risk ratings.

### Agent 3: Remediation
Takes confirmed vulnerabilities and generates actionable fixes. Produces diff-ready patches, explanatory comments, and prevention recommendations. Each fix is validated against original code context.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan a directory
sentinel scan ./my-project

# Scan with specific agents
sentinel scan ./my-project --agents scanner,analyzer

# Output as JSON
sentinel scan ./my-project --format json --output report.json
```

## Configuration

Create `sentinel.yaml` in your project root:

```yaml
model: mimo-v2.5-pro
severity_threshold: medium
exclude_patterns:
  - "*/test/*"
  - "*.min.js"
max_file_size_kb: 500
```

## License

MIT
