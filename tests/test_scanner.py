"""Tests for the Scanner Agent."""

import tempfile
from pathlib import Path

from sentinel.config import SentinelConfig
from sentinel.scanner.agent import ScannerAgent


def test_scan_finds_sql_injection():
    """Scanner should detect SQL injection patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        vuln_file = Path(tmpdir) / "app.py"
        vuln_file.write_text(
            'import sqlite3\n'
            'def get_user(user_id):\n'
            '    conn = sqlite3.connect("db.sqlite")\n'
            '    cursor = conn.cursor()\n'
            '    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n'
            '    return cursor.fetchone()\n'
        )
        config = SentinelConfig(exclude_patterns=[])
        scanner = ScannerAgent(config)
        output = scanner.scan_directory(tmpdir)

        assert output.files_scanned == 1
        assert len(output.findings) > 0
        cwe_ids = [f.cwe for f in output.findings]
        assert "CWE-89" in cwe_ids


def test_scan_finds_hardcoded_secret():
    """Scanner should detect hardcoded credentials."""
    with tempfile.TemporaryDirectory() as tmpdir:
        vuln_file = Path(tmpdir) / "config.py"
        vuln_file.write_text(
            'api_key = "sk-abc123def456ghi789jkl012mno345"\n'
            'password = "super_secret_password_123"\n'
        )
        config = SentinelConfig(exclude_patterns=[])
        scanner = ScannerAgent(config)
        output = scanner.scan_directory(tmpdir)

        assert len(output.findings) > 0
        cwe_ids = [f.cwe for f in output.findings]
        assert "CWE-798" in cwe_ids


def test_scan_excludes_patterns():
    """Scanner should respect exclude patterns."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dir = Path(tmpdir) / "test"
        test_dir.mkdir()
        (test_dir / "test_app.py").write_text(
            'password = "test_password_123456"\n'
            'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n'
        )
        config = SentinelConfig(exclude_patterns=["*/test/*"])
        scanner = ScannerAgent(config)
        output = scanner.scan_directory(tmpdir)

        assert output.files_scanned == 0
        assert len(output.findings) == 0


def test_scan_clean_code():
    """Scanner should not flag clean code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        clean_file = Path(tmpdir) / "clean.py"
        clean_file.write_text(
            'import os\n'
            'def greet(name: str) -> str:\n'
            '    return f"Hello, {name}!"\n'
            '\n'
            'def add(a: int, b: int) -> int:\n'
            '    return a + b\n'
        )
        config = SentinelConfig(exclude_patterns=[])
        scanner = ScannerAgent(config)
        output = scanner.scan_directory(tmpdir)

        assert output.files_scanned == 1
        assert len(output.findings) == 0
