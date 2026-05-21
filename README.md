<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/MiMo-Powered-orange?logo=xiaomi&logoColor=white" alt="MiMo Powered">
  <img src="https://img.shields.io/badge/Security-Multi--Agent-red?logo=shield&logoColor=white" alt="Multi-Agent Security">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg" alt="PRs Welcome">
</p>

<h1 align="center">🛡️ mimo-code-sentinel</h1>

<p align="center">
  <b>Multi-agent code security scanner powered by MiMo AI</b><br>
  A 3-agent sequential pipeline that scans, analyzes, and remediates security vulnerabilities in your codebase.<br>
  <sub>Built for the <a href="https://100t.xiaomimimo.com">Xiaomi MiMo 100T Token Program</a></sub>
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [How It Works](#-how-it-works)
- [Supported Vulnerabilities](#-supported-vulnerabilities)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [CLI Usage](#-cli-usage)
- [Configuration](#-configuration)
- [API Usage](#-api-usage)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Design Decisions](#-design-decisions)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**mimo-code-sentinel** solves a fundamental problem in code security: **manual code reviews are slow, inconsistent, and can't scale across large codebases**. A single LLM pass often misses context-dependent vulnerabilities that require understanding data flow across multiple files.

Sentinel uses a **3-agent sequential pipeline** where each agent builds on the previous agent's structured output:

1. **Scanner Agent** — Fast, deterministic pattern matching (no LLM needed)
2. **Analyzer Agent** — Contextual reasoning with data-flow tracing
3. **Remediation Agent** — Actionable fix generation with diff-ready patches

The key design principle: **each agent operates on structured JSON from the previous stage**, enabling deterministic handoffs while allowing the LLM to focus on domain-specific reasoning at each step.

### Why Multi-Agent?

| Approach | Strengths | Weaknesses |
|----------|-----------|------------|
| Single LLM pass | Simple, fast | Misses cross-file context, hallucinates locations |
| Rule-based scanner (Semgrep, etc.) | Fast, deterministic | No contextual reasoning, high false positive rate |
| **Sentinel (3-agent)** | **Combines deterministic scanning with LLM reasoning** | Slightly more complex pipeline |

Sentinel doesn't replace tools like Semgrep or CodeQL — it **complements** them by adding an LLM reasoning layer on top of pattern-based findings to drastically reduce false positives.

---

## 🏗️ Architecture

```
┌─────────────────────┐         ┌──────────────────────┐         ┌─────────────────────┐
│                     │  JSON   │                      │  JSON   │                     │
│   🔍 SCANNER AGENT  │────────▶│   🧠 ANALYZER AGENT  │────────▶│   🔧 REMEDIATION    │
│                     │         │                      │         │      AGENT          │
└─────────────────────┘         └──────────────────────┘         └─────────────────────┘
                                                                  
  • AST parsing                   • Data-flow tracing             • Diff-ready patches
  • Regex pattern matching        • True/false positive           • Fix templates per CWE
  • CWE classification              classification                • Prevention recommendations
  • Severity scoring              • Confidence scoring            • Context validation
                                  • Attack scenario gen
```

### Data Flow

```
Source Code (files)
       │
       ▼
┌──────────────────┐     ScannerOutput (JSON)
│  Scanner Agent   │────────────────────────────┐
│  ─────────────── │                             │
│  • Walk directory│                             ▼
│  • Apply rules   │                   ┌──────────────────┐
│  • Match patterns│     AnalyzerOutput│  Analyzer Agent   │
│                  │       (JSON)      │  ──────────────── │
└──────────────────┘                   │  • Trace data flow│
       ▲                               │  • Classify TP/FP │
       │                               │  • Score confidence│
   sentinel.yaml                       └──────────────────┘
   (config)                                     │
                                                ▼
                                      ┌──────────────────┐
                                      │  Remediation     │
                                      │  ──────────────── │
                                      │  • Generate patch │
                                      │  • Explain fix    │
                                      │  • Prevention tips│
                                      └──────────────────┘
                                                │
                                                ▼
                                        JSON Report /
                                        Terminal Output
```

---

## ⚙️ How It Works

### Agent 1: Scanner

The Scanner performs **deterministic, rule-based static analysis** — no LLM calls needed at this stage. It:

1. **Walks the directory tree**, filtering by file extension and exclude patterns
2. **Applies regex rules** from a built-in rule database (10 rules covering 7 CWE categories)
3. **Outputs structured JSON** with exact file paths, line numbers, code snippets, severity scores, and CWE classifications

The Scanner is intentionally conservative — it **over-reports** to avoid missing real issues. False positive elimination is delegated to the Analyzer.

**Example Scanner output:**
```json
{
  "findings": [
    {
      "rule_id": "SQL-001",
      "cwe": "CWE-89",
      "severity": "high",
      "file_path": "app/db.py",
      "line_start": 23,
      "line_end": 23,
      "code_snippet": "cursor.execute(\"SELECT * FROM users WHERE id = %s\" % user_id)",
      "description": "Potential SQL injection via string formatting in query",
      "confidence": 0.6
    }
  ]
}
```

### Agent 2: Analyzer

The Analyzer receives Scanner JSON and performs **contextual reasoning**:

1. **Extracts the suspicious variable** from the flagged code
2. **Traces data flow backward** (up to 20 lines) looking for:
   - **Sources**: `request.args`, `input()`, `sys.argv`, environment variables
   - **Sanitizers**: `escape()`, `sanitize()`, parameterized queries, type coercion
3. **Classifies** each finding as true positive or false positive with a confidence score
4. **Generates attack scenarios** describing how an attacker would exploit the vulnerability
5. **Computes risk ratings** based on `severity × confidence × taint_factor`

**Key insight**: A regex match for SQL injection in test code with no user input is a **false positive**. The same pattern in a route handler receiving `request.args` is a **true positive**. The Analyzer makes this distinction.

### Agent 3: Remediation

The Remediation Agent takes confirmed true positives and generates **actionable fixes**:

1. **Maps CWE to fix templates** — each CWE has language-specific fix patterns
2. **Generates unified diffs** showing exact code changes
3. **Writes developer-friendly explanations** referencing the specific vulnerability
4. **Provides prevention recommendations** to avoid similar issues in the future

**Example patch output:**
```diff
--- a/app/db.py
+++ b/app/db.py
@@ -20,6 +20,8 @@
 def get_user(user_id):
     conn = sqlite3.connect("db.sqlite")
     cursor = conn.cursor()
-    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
+    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
+    # SECURITY FIX (CWE-89): Use parameterized queries instead of string formatting
```

---

## 🎯 Supported Vulnerabilities

| CWE | Category | Severity | Languages |
|-----|----------|----------|-----------|
| **CWE-89** | SQL Injection | 🔴 High | Python, JavaScript, Java, PHP |
| **CWE-79** | Cross-Site Scripting (XSS) | 🟡 Medium | JavaScript, TypeScript, Vue |
| **CWE-78** | Command Injection | 🔴 High | Python |
| **CWE-22** | Path Traversal | 🔴 High | All |
| **CWE-502** | Unsafe Deserialization | 🔴 Critical | Python |
| **CWE-798** | Hardcoded Credentials | 🔴 Critical | All |
| **CWE-327** | Weak Cryptography | 🟡 Medium | All |

### Patterns Detected

- **SQL Injection**: String formatting/concatenation in `execute()`, `query()`, `raw()` calls
- **Hardcoded Secrets**: Passwords, API keys, AWS keys (`AKIA...`), OpenAI keys (`sk-...`), GitHub tokens (`ghp_...`)
- **Command Injection**: `os.system()`, `os.popen()`, `subprocess` with `shell=True` or string formatting
- **Path Traversal**: `open()`, `send_file()` with user-controlled input
- **Unsafe Deserialization**: `pickle.loads()`, `yaml.load()`, `marshal.loads()`
- **XSS**: `innerHTML`, `outerHTML`, `document.write`, `v-html`
- **Weak Crypto**: MD5, SHA1, DES, RC4, ECB mode usage

---

## 📦 Installation

### From source

```bash
# Clone the repository
git clone https://github.com/kaidendestroyer/mimo-code-sentinel.git
cd mimo-code-sentinel

# Install in development mode
pip install -e ".[dev]"
```

### Dependencies

- **Python ≥ 3.10** (uses `match` statements, `X | Y` union types)
- **openai ≥ 1.0** — LLM client for Analyzer/Remediation (future: MiMo API)
- **pyyaml ≥ 6.0** — Configuration parsing
- **rich ≥ 13.0** — Terminal UI (tables, panels, syntax highlighting)
- **click ≥ 8.0** — CLI framework
- **tree-sitter ≥ 0.20** — AST parsing (future enhancement)

---

## 🚀 Quick Start

```bash
# 1. Clone and install
git clone https://github.com/kaidendestroyer/mimo-code-sentinel.git
cd mimo-code-sentinel
pip install -e .

# 2. Scan your project
sentinel scan /path/to/your/project

# 3. Get JSON output for CI/CD
sentinel scan /path/to/your/project --format json --output report.json
```

That's it! Sentinel will run all 3 agents and display findings in a rich terminal table.

---

## 💻 CLI Usage

### `sentinel scan`

The main command. Runs the full 3-agent pipeline on a target directory.

```bash
sentinel scan <PATH> [OPTIONS]
```

**Options:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | `sentinel.yaml` | Path to configuration file |
| `--format` | `-f` | `table` | Output format: `table` or `json` |
| `--output` | `-o` | stdout | Output file path (for JSON format) |
| `--severity` | `-s` | `medium` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` |
| `--agents` | | `scanner,analyzer,remediation` | Comma-separated list of agents to run |
| `--no-remediation` | | `false` | Skip the Remediation agent |

**Examples:**

```bash
# Full scan with table output
sentinel scan ./src

# JSON report for CI/CD pipeline
sentinel scan ./src --format json --output security-report.json

# Only run Scanner (fast, no LLM needed)
sentinel scan ./src --agents scanner

# Run Scanner + Analyzer only (no patches)
sentinel scan ./src --no-remediation

# Only show critical and high severity
sentinel scan ./src --severity high

# Custom config file
sentinel scan ./src --config ./security/sentinel.yaml
```

### `sentinel init`

Initialize a `sentinel.yaml` configuration file in a project directory.

```bash
sentinel init /path/to/project
```

---

## ⚡ Configuration

Create a `sentinel.yaml` file in your project root:

```yaml
# Model configuration
model: mimo-v2.5-pro
api_base: https://api.mimo.ai/v1

# Scan settings
severity_threshold: medium    # minimum severity to report
max_file_size_kb: 500         # skip files larger than this

# Exclude patterns (glob syntax)
exclude_patterns:
  - "*/test/*"
  - "*/tests/*"
  - "*/node_modules/*"
  - "*/.git/*"
  - "*/venv/*"
  - "*/__pycache__/*"
  - "*.min.js"
  - "*.min.css"
  - "*.pyc"
  - "*.map"

# CWE categories to check (comment out to disable)
cwe_categories:
  - "CWE-89"   # SQL Injection
  - "CWE-79"   # Cross-Site Scripting
  - "CWE-78"   # Command Injection
  - "CWE-22"   # Path Traversal
  - "CWE-502"  # Unsafe Deserialization
  - "CWE-798"  # Hardcoded Credentials
  - "CWE-327"  # Weak Cryptography

# Advanced settings
timeout_seconds: 120
max_retries: 3
```

### Environment Variables

You can also configure via environment variables (overrides YAML):

```bash
export SENTINEL_API_KEY="your-mimo-api-key"
export SENTINEL_API_BASE="https://api.mimo.ai/v1"
export SENTINEL_MODEL="mimo-v2.5-pro"
```

---

## 🔌 API Usage

Use Sentinel programmatically in your Python code:

### Full Pipeline

```python
from sentinel.config import SentinelConfig
from sentinel.pipeline import Pipeline

# Load config
config = SentinelConfig.from_file("sentinel.yaml")

# Run full pipeline
pipeline = Pipeline(config)
result = pipeline.run("./my-project")

# Access results
print(f"Files scanned: {result.scanner_output.files_scanned}")
print(f"Total findings: {result.total_findings}")
print(f"True positives: {result.true_positives}")
print(f"Patches generated: {result.patches_generated}")
print(f"Timing: {result.timings}")

# Export as JSON
report = result.to_json()
```

### Individual Agents

```python
from sentinel.scanner.agent import ScannerAgent
from sentinel.analyzer.agent import AnalyzerAgent
from sentinel.remediation.agent import RemediationAgent
from sentinel.config import SentinelConfig

config = SentinelConfig()

# Agent 1: Scanner only
scanner = ScannerAgent(config)
scan_result = scanner.scan_directory("./src")
print(f"Found {len(scan_result.findings)} issues")

# Agent 2: Analyzer (needs Scanner output)
analyzer = AnalyzerAgent(config, base_path="./src")
analysis = analyzer.analyze(scan_result)
for f in analysis.enriched_findings:
    verdict = "TRUE POSITIVE" if f.is_true_positive else "FALSE POSITIVE"
    print(f"  [{verdict}] {f.finding.cwe} @ {f.finding.file_path}:{f.finding.line_start}")
    print(f"    Confidence: {f.confidence_score:.0%}")
    print(f"    Attack: {f.attack_scenario}")

# Agent 3: Remediation (needs Analyzer output)
remediator = RemediationAgent(config)
remediation = remediator.remediate(analysis)
for patch in remediation.patches:
    print(f"\nPatch for {patch.file_path}:")
    print(patch.diff)
```

### Data Models

All inter-agent communication uses typed dataclasses with JSON serialization:

```python
from sentinel.models import (
    Finding, Severity, ScannerOutput,      # Scanner → Analyzer
    EnrichedFinding, AnalyzerOutput,        # Analyzer → Remediation
    RemediationPatch, RemediationOutput,    # Final output
)

# Parse Scanner output from JSON
scanner_output = ScannerOutput.from_json(json_string)

# Serialize any output to JSON
json_str = scanner_output.to_json()
json_str = analyzer_output.to_json()
json_str = remediation_output.to_json()
```

---

## 📁 Project Structure

```
mimo-code-sentinel/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── setup.py                           # Package configuration
├── sentinel.yaml                      # Default config template
├── .github/
│   └── workflows/
│       └── test.yml                   # CI: pytest on Python 3.10-3.12
│
├── sentinel/                          # Main package
│   ├── __init__.py                    # Package init, version
│   ├── config.py                      # YAML + env config loading
│   ├── models.py                      # Data models for JSON handoffs
│   ├── pipeline.py                    # Pipeline orchestrator
│   ├── cli.py                         # Click CLI entry point
│   │
│   ├── scanner/                       # Agent 1: Static Analysis
│   │   ├── __init__.py
│   │   ├── agent.py                   # ScannerAgent class
│   │   └── rules.py                   # Built-in rule definitions
│   │
│   ├── analyzer/                      # Agent 2: Contextual Analysis
│   │   ├── __init__.py
│   │   ├── agent.py                   # AnalyzerAgent class
│   │   └── dataflow.py               # Data-flow tracing engine
│   │
│   └── remediation/                   # Agent 3: Fix Generation
│       ├── __init__.py
│       └── agent.py                   # RemediationAgent class
│
├── tests/                             # Test suite
│   ├── __init__.py
│   └── test_scanner.py               # Scanner unit tests
│
└── examples/                          # Usage examples
    └── run_scan.py                    # Full pipeline example
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=sentinel --cov-report=term-missing

# Run specific test
pytest tests/test_scanner.py::test_scan_finds_sql_injection -v
```

### Test Coverage

| Module | Tests | Status |
|--------|-------|--------|
| Scanner Agent | 4 tests | ✅ SQL injection, secrets, exclusions, clean code |
| Analyzer Agent | (planned) | 🔜 |
| Remediation Agent | (planned) | 🔜 |
| Pipeline | (planned) | 🔜 |

---

## 🧠 Design Decisions

### 1. Why Sequential Pipeline (not DAG)?

The security scanning workflow is inherently sequential: you can't analyze findings before scanning, and you can't remediate before analyzing. A DAG would add unnecessary complexity for a linear data flow.

### 2. Why Regex First, LLM Second?

Regex-based scanning is **fast** (~1000 files/second), **deterministic**, and **zero-cost**. Running an LLM on every file would be expensive and slow. The Scanner casts a wide net; the Analyzer uses LLM reasoning only on flagged code to filter false positives.

### 3. Why Structured JSON Handoffs?

Each agent outputs **typed, validated JSON** rather than free-form text. This:
- Enables deterministic testing of each agent in isolation
- Prevents LLM hallucination from propagating between agents
- Allows swapping agents (e.g., replacing regex Scanner with Semgrep)
- Makes the pipeline debuggable — you can inspect each stage's output

### 4. Why Not Use Semgrep/CodeQL Directly?

Sentinel doesn't replace Semgrep — it **wraps** pattern-based scanning with an LLM reasoning layer. The Scanner stage could be replaced by Semgrep rules (future enhancement). The value-add is the Analyzer's contextual reasoning that eliminates false positives.

---

## 🗺️ Roadmap

- [ ] **Tree-sitter AST parsing** — More accurate pattern matching beyond regex
- [ ] **Semgrep integration** — Use Semgrep rules as Scanner backend
- [ ] **MiMo API integration** — Use MiMo models for Analyzer/Remediation agents
- [ ] **GitHub Action** — `sentinel-action` for PR comments with security findings
- [ ] **SARIF output** — Integration with GitHub Code Scanning / VS Code
- [ ] **Custom rule engine** — User-defined rules in YAML
- [ ] **Incremental scanning** — Only scan changed files (git diff aware)
- [ ] **Multi-language AST** — Go, Rust, Java, PHP support via tree-sitter grammars
- [ ] **IDE plugin** — VS Code extension for inline security warnings
- [ ] **Docker image** — `docker run sentinel scan /src`

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Commit** your changes: `git commit -m "feat: add my feature"`
4. **Push** to the branch: `git push origin feature/my-feature`
5. **Open** a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/mimo-code-sentinel.git
cd mimo-code-sentinel

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linter
ruff check sentinel/ tests/
```

### Adding New Rules

To add a new scanning rule, edit `sentinel/scanner/rules.py`:

```python
ScanRule(
    rule_id="MY-001",
    cwe="CWE-XXX",
    pattern=re.compile(r"your_regex_pattern"),
    severity="high",  # critical, high, medium, low, info
    description="Human-readable description of the vulnerability",
    languages=["python"],  # or None for all languages
)
```

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>Built with ❤️ for the <a href="https://100t.xiaomimimo.com">Xiaomi MiMo 100T Token Program</a></sub><br>
  <sub>By <a href="https://github.com/kaidendestroyer">@kaidendestroyer</a></sub>
</p>
