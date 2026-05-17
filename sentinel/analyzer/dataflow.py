"""Simple data-flow tracing for determining if findings are true positives."""

import re
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class DataFlowNode:
    """Represents a node in a data flow graph."""
    file_path: str
    line: int
    code: str
    is_source: bool = False   # user input, request params, etc.
    is_sink: bool = False     # SQL query, command exec, etc.
    variable: str = ""


@dataclass
class DataFlowTrace:
    """Traces how data flows from sources to sinks."""
    nodes: list[DataFlowNode] = field(default_factory=list)
    is_tainted: bool = False
    sanitizers_found: list[str] = field(default_factory=list)


# Patterns that indicate user-controlled input sources
SOURCE_PATTERNS = [
    re.compile(r"""request\.(?:args|form|json|data|GET|POST|params)"""),
    re.compile(r"""input\s*\("""),
    re.compile(r"""sys\.argv"""),
    re.compile(r"""(?:argv|environ|getenv)"""),
    re.compile(r"""(?:req\.body|req\.query|req\.params)"""),
]

# Patterns that indicate sanitization
SANITIZER_PATTERNS = [
    re.compile(r"""(?:escape|sanitize|bleach\.clean|html\.escape|cgi\.escape)"""),
    re.compile(r"""(?:parameterized|prepared|placeholder)"""),
    re.compile(r"""(?:re\.escape|shlex\.quote|quote_plus)"""),
    re.compile(r"""(?:int\(|float\(|Decimal\()"""),  # type coercion
]


class DataFlowAnalyzer:
    """Traces data flow from user-controlled sources to security sinks."""

    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self._file_cache: dict[str, list[str]] = {}

    def trace_variable(
        self, variable: str, file_path: str, line: int
    ) -> DataFlowTrace:
        """Attempt to trace a variable from its definition to usage."""
        trace = DataFlowTrace()
        
        # Get the file contents
        lines = self._read_file(file_path)
        if not lines:
            return trace

        # Look backward from the finding to find variable assignment
        for i in range(max(0, line - 20), line):
            code = lines[i] if i < len(lines) else ""
            
            # Check if variable is assigned from a source
            for pattern in SOURCE_PATTERNS:
                if variable in code and pattern.search(code):
                    trace.nodes.append(DataFlowNode(
                        file_path=file_path,
                        line=i + 1,
                        code=code.strip(),
                        is_source=True,
                        variable=variable,
                    ))
                    trace.is_tainted = True
                    break

            # Check for sanitizers
            for pattern in SANITIZER_PATTERNS:
                if variable in code and pattern.search(code):
                    trace.sanitizers_found.append(code.strip())

        # Mark the sink
        sink_line = lines[line - 1] if line <= len(lines) else ""
        trace.nodes.append(DataFlowNode(
            file_path=file_path,
            line=line,
            code=sink_line.strip(),
            is_sink=True,
            variable=variable,
        ))

        return trace

    def _read_file(self, rel_path: str) -> list[str]:
        """Read file with caching."""
        if rel_path not in self._file_cache:
            full_path = self.base_path / rel_path
            try:
                self._file_cache[rel_path] = full_path.read_text(errors="replace").split("\n")
            except (OSError, PermissionError):
                self._file_cache[rel_path] = []
        return self._file_cache[rel_path]
