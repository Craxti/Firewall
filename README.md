# 🔥 Firewall - Advanced Python Firewall Management Framework

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-37%20passed-brightgreen.svg)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-37%25-orange.svg)](htmlcov/)

A powerful, cross-platform Python framework for automated firewall configuration and management. Supports both Linux (iptables) and Windows (PowerShell) environments with a unified API.

## ✨ Features

- 🐧 **Linux Support**: Full iptables integration with advanced rule management
- 🪟 **Windows Support**: PowerShell-based Windows Firewall automation
- 🔧 **Cross-Platform**: Unified API for both Linux and Windows
- 📝 **Configuration Management**: INI-based configuration with validation
- 🧪 **Comprehensive Testing**: 37 unit and integration tests
- 🎨 **Modern Python**: F-strings, type hints, and Python 3.9+ features
- 🚀 **Easy Integration**: Simple API for firewall rule management

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/firewall.git
cd firewall

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Basic Usage

```python
from firewall.interact.set_firewall import SetFirewall
from firewall.windows.adapter import WindowsFirewallAdapter

# Linux firewall
firewall = SetFirewall(verbose=1, execute=True)
firewall.allow_dhcp()
firewall.allow_ping()
firewall.deny_all()

# Windows firewall
windows_firewall = WindowsFirewallAdapter(verbose=1, execute=True)
windows_firewall.allow_dhcp()
windows_firewall.allow_ping()
windows_firewall.deny_all()
```

## 📖 Documentation

### Linux Firewall (iptables)

```python
# Basic operations
firewall = SetFirewall(verbose=1, execute=True)

# Allow specific services
firewall.allow_dhcp()           # Allow DHCP traffic
firewall.allow_ping()          # Allow ICMP ping
firewall.allow_localhost()     # Allow localhost traffic

# Network transport rules
firewall.allow_network_transport(
    direction='inbound',
    protocol='tcp',
    ports=[80, 443],
    networks='192.168.1.0/24',
    policy='ACCEPT'
)

# Block specific networks
firewall.set_nostrike(['192.168.1.100/32', '10.0.0.0/8'])

# Policy management
firewall.allow_all()    # Allow all traffic
firewall.deny_all()     # Deny all traffic (default)
```

### Windows Firewall (PowerShell)

```python
# Windows firewall operations
windows_firewall = WindowsFirewallAdapter(verbose=1, execute=True)

# Allow services
windows_firewall.allow_dhcp()
windows_firewall.allow_ping()

# Network rules
windows_firewall.allow_network_transport(
    direction='outbound',
    protocol='tcp',
    ports=[80, 443],
    networks='0.0.0.0/0'
)

# Block networks
windows_firewall.set_nostrike(['192.168.1.100/32'])
```

## ⚙️ Configuration

Create a configuration file (`config.ini`):

```ini
[local_config]
iface=eth0
rh_host=firewall-server
rh_ipaddr=192.168.1.100
netmask=255.255.255.0
gateway_addr=192.168.1.1
dns=8.8.8.8

[firewall_config]
target_range=10.0.0.0/8
trusted_range=192.168.1.0/24
nostrike=192.168.1.5/32

[security_settings]
log_exceptions=true
disallow_ping=false
allow_outbound_icmp=true
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=firewall --cov-report=html

# Run specific test categories
pytest -m "not integration"  # Unit tests only
pytest -m integration          # Integration tests only
```

## 📊 Test Results

- ✅ **37 tests passed**
- 📈 **37% code coverage**
- 🐧 **Linux support**: iptables integration
- 🪟 **Windows support**: PowerShell automation
- 🔧 **Cross-platform**: Unified API

## 🛠️ Development

### Code Quality

```bash
# Linting
flake8 firewall

# Formatting
black firewall
isort firewall

# Type checking
mypy firewall
```

### GitHub Actions

The project includes automated CI/CD with GitHub Actions:

- ✅ Python 3.9 support
- ✅ Cross-platform testing (Linux, Windows, macOS)
- ✅ Code quality checks
- ✅ Automated testing

## 📁 Project Structure

```
firewall/
├── firewall/
│   ├── base/           # Core functionality
│   ├── interact/       # Firewall operations
│   ├── utils/          # Utilities
│   └── windows/        # Windows-specific code
├── tests/              # Test suite
├── configs/            # Configuration examples
└── docs/              # Documentation
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Linux iptables community
- Windows PowerShell team
- Python community for excellent tooling

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/yourusername/firewall/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/firewall/discussions)
- 📧 **Email**: support@firewall-project.com

---

**Made with ❤️ for the open source community**