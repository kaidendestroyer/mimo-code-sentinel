"""Configuration loading and management."""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

import yaml


@dataclass
class SentinelConfig:
    """Runtime configuration for the scanner pipeline."""
    model: str = "mimo-v2.5-pro"
    api_base: str = "https://api.mimo.ai/v1"
    api_key: Optional[str] = None
    severity_threshold: str = "medium"
    max_file_size_kb: int = 500
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "*/test/*", "*/node_modules/*", "*.min.js", "*.pyc", "__pycache__/*"
    ])
    cwe_categories: list[str] = field(default_factory=lambda: [
        "CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-502", "CWE-798"
    ])
    timeout_seconds: int = 120
    max_retries: int = 3

    @classmethod
    def from_file(cls, path: str | Path = "sentinel.yaml") -> "SentinelConfig":
        """Load config from YAML file, falling back to defaults."""
        config_path = Path(path)
        if not config_path.exists():
            return cls()
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_env(cls) -> "SentinelConfig":
        """Load config from environment variables."""
        config = cls()
        config.api_key = os.environ.get("SENTINEL_API_KEY") or os.environ.get("MIMO_API_KEY")
        config.api_base = os.environ.get("SENTINEL_API_BASE", config.api_base)
        config.model = os.environ.get("SENTINEL_MODEL", config.model)
        return config
