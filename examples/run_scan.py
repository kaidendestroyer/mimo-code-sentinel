#!/usr/bin/env python3
"""Example: run the full security scanning pipeline."""

from sentinel.config import SentinelConfig
from sentinel.pipeline import Pipeline


def main():
    config = SentinelConfig.from_file("sentinel.yaml")
    pipeline = Pipeline(config)

    result = pipeline.run("./sample_project")

    print(result.to_json())


if __name__ == "__main__":
    main()
