from setuptools import find_packages, setup

setup(
    name="firewall",
    version="3.0",
    platforms=["any"],
    long_description='Firewall configuration generator and implementor for Cyber Network Defenders. ',
    packages=find_packages(),
    scripts=['bin/firewall', 'bin/bs'],
    author="Alexksandr Fetisov",
    author_email="fetis.dev@gmail.com"

)
