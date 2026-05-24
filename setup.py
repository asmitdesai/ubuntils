import re
import pathlib
from setuptools import setup, find_packages


def get_version():
    text = pathlib.Path("ubuntils/__init__.py").read_text()
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    if not match:
        raise RuntimeError("Cannot find __version__ in ubuntils/__init__.py")
    return match.group(1)


setup(
    name="ubuntils",
    version=get_version(),
    description="Ubuntu incident response tool for forensic artifact collection and detection",
    author="Asmit Desai",
    author_email="asmitdesai02@gmail.com",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.0",
        "textual>=0.50.0",
        "structlog>=24.0.0",
        "pyyaml>=6.0",
        "python-dateutil>=2.8",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ubuntils=ubuntils.cli:main",
        ],
    },
    python_requires=">=3.8",
)
