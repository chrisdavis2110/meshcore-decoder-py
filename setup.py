"""
Setup configuration for meshcore-decoder-py
"""

from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Find all packages in the current directory (will find 'meshcoredecoder' and its subpackages)
all_packages = find_packages()

setup(
    name="meshcoredecoder",
    version="0.1.0",
    author="Chris Davis",
    author_email="chrisdavis2110@gmail.com",
    description="Complete Python implementation of the MeshCore Packet Decoder",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/chrisdavis2110/meshcore-decoder-py",
    packages=all_packages,
    # Include root-level modules (cli.py and index.py)
    py_modules=["cli", "index"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome>=3.19.0",
        "cryptography>=41.0.0",
        "click>=8.1.0",
    ],
    entry_points={
        "console_scripts": [
            "meshcore-decode=cli:main",
        ],
    },
    include_package_data=True,
)