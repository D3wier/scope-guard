from setuptools import setup, find_packages

setup(
    name="scope-guard",
    version="0.1.0",
    description="Bug bounty program scope checker — real-time in-scope/out-of-scope verdicts",
    author="D3wier",
    url="https://github.com/D3wier/scope-guard",
    packages=find_packages(),
    install_requires=["pyyaml>=6.0"],
    entry_points={
        "console_scripts": [
            "scope-guard=scope_guard.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
