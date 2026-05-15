from setuptools import setup, find_packages

setup(
    name="mimo-code-sentinel",
    version="0.1.0",
    description="Multi-agent code security scanner built with MiMo AI",
    author="Joko Wijaya",
    author_email="kaidendestroyer@zetolabs.xyz",
    url="https://github.com/kaidendestroyer/mimo-code-sentinel",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[
        "openai>=1.0.0",
        "pyyaml>=6.0",
        "rich>=13.0",
        "click>=8.0",
        "tree-sitter>=0.20",
    ],
    entry_points={
        "console_scripts": [
            "sentinel=sentinel.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
