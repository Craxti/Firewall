from setuptools import find_packages, setup
import os

# Read the contents of README.md for long_description
with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

# Read requirements.txt
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="firewall",
    version="3.1.0",
    platforms=["any"],
    description="Firewall configuration tool for cybersecurity professionals",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    scripts=['bin/firewall', 'bin/bs'],
    author="Alexksandr Fetisov",
    author_email="fetis.dev@gmail.com",
    url="https://github.com/fetis/firewall",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: Security",
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    include_package_data=True,
    keywords="firewall, security, networking, iptables, windows firewall",
    project_urls={
        "Bug Tracker": "https://github.com/fetis/firewall/issues",
        "Documentation": "https://github.com/fetis/firewall/blob/main/README.md",
        "Source Code": "https://github.com/fetis/firewall",
    },
)
