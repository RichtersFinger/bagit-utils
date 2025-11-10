import os
from pathlib import Path
from setuptools import setup


try:
    long_description = (Path(__file__).parent / "README.md").read_text(
        encoding="utf8"
    )
except FileNotFoundError:
    long_description = (
        "See docs at https://github.com/RichtersFinger/bagit-utils"
    )


setup(
    version=os.environ.get("VERSION", "1.2.3"),
    name="bagit-utils",
    description=(
        "python library and command line interface for creating and "
        + "interacting with files in the BagIt-format"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Steffen Richters-Finger",
    author_email="srichters@uni-muenster.de",
    license="MIT",
    url="https://pypi.org/project/bagit-utils/",
    project_urls={"Source": "https://github.com/RichtersFinger/bagit-utils"},
    python_requires=">=3.10",
    install_requires=[],
    packages=[
        "bagit_utils",
    ],
    extras_require={
        "cli": ["befehl>=0.1.2,<1.0.0",]
    },
    entry_points={"console_scripts": ["bagit = bagit_utils.cli:cli"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "Topic :: Communications :: File Sharing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
