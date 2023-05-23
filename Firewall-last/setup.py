from setuptools import setup

setup(
    name='firewall-system',
    version='1.0.0',
    author='Aleksandr',
    description='Firewall System for network traffic filtering',
    packages=[
        'firewall',
        'rule',
        'condition',
        'action',
        'packet_processor',
        'intrusion_detection',
        'network_monitor',
        'packet_processor'
    ],
    install_requires=[
        'cffi',
        'click',
        'colorama',
        'cryptography',
        'Flask',
        'itsdangerous,'
        'Jinja2',
        'logger',
        'MarkupSafe',
        'pycparser',
        'scapy',
        'Werkzeug',
        'psutil',
        'numba',
        'blinker',
        'scikit-learn',
    ],
)
