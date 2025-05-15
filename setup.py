#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="webscann3r",
    version="0.1.0",
    author="WebScann3r Contributors",
    author_email="author@example.com",
    description="A web scanner and mapper for red team assessments",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/webscann3r",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "webscann3r=webscann3r:main",
        ],
    },
)
