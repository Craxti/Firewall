# 🤝 Contributing to Firewall

Thank you for your interest in contributing to the Firewall project! This document provides guidelines for contributing to this open source project.

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Git
- Basic knowledge of firewall concepts
- Familiarity with iptables (Linux) or Windows Firewall (Windows)

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/firewall.git
cd firewall

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run tests to ensure everything works
pytest
```

## 🧪 Testing

We maintain high code quality with comprehensive testing:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=firewall --cov-report=html

# Run specific test categories
pytest -m "not integration"  # Unit tests only
pytest -m integration          # Integration tests only
```

## 📝 Code Style

We follow modern Python best practices:

- **F-strings**: Use f-strings instead of .format() or % formatting
- **Type hints**: Add type hints where appropriate
- **Docstrings**: Document all public functions and classes
- **Error handling**: Use specific exceptions, not bare `except:`

### Example of good code:

```python
def allow_network_transport(
    self, 
    direction: str, 
    protocol: str = 'tcp', 
    ports: Optional[List[int]] = None,
    networks: str = '0.0.0.0/0',
    policy: str = 'ACCEPT'
) -> None:
    """
    Allow network transport with specified parameters.
    
    Args:
        direction: Traffic direction ('inbound' or 'outbound')
        protocol: Network protocol ('tcp' or 'udp')
        ports: List of port numbers (optional)
        networks: Network address or CIDR
        policy: Action to take ('ACCEPT', 'DROP', 'REJECT')
    """
    if direction not in ['inbound', 'outbound']:
        raise ValueError("Direction must be 'inbound' or 'outbound'")
    
    # Implementation here...
```

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Environment**: OS, Python version, firewall type
2. **Steps to reproduce**: Clear, numbered steps
3. **Expected behavior**: What should happen
4. **Actual behavior**: What actually happens
5. **Error messages**: Full error traceback
6. **Configuration**: Relevant config files

## ✨ Feature Requests

For new features, please:

1. Check existing issues first
2. Describe the use case clearly
3. Explain why it would be valuable
4. Consider implementation complexity
5. Provide examples if possible

## 🔧 Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Make** your changes following our code style
4. **Add** tests for new functionality
5. **Update** documentation if needed
6. **Run** tests: `pytest`
7. **Commit** with clear messages: `git commit -m 'Add amazing feature'`
8. **Push** to your branch: `git push origin feature/amazing-feature`
9. **Open** a Pull Request

### PR Guidelines

- **Title**: Clear, descriptive title
- **Description**: Explain what and why
- **Tests**: Include test cases
- **Documentation**: Update docs if needed
- **Breaking changes**: Clearly mark them

## 📚 Documentation

When adding new features:

1. **Update README.md** if it affects basic usage
2. **Add docstrings** to all public functions
3. **Update examples** in the examples/ directory
4. **Add type hints** for better IDE support

## 🏷️ Release Process

Releases are managed through GitHub Actions:

1. **Version bump**: Update version in setup.py
2. **Changelog**: Update CHANGELOG.md
3. **Tag**: Create a git tag
4. **Release**: GitHub Actions handles the rest

## 🤔 Questions?

- **Discussions**: Use GitHub Discussions for questions
- **Issues**: Use GitHub Issues for bugs and features
- **Email**: Contact maintainers for sensitive issues

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to Firewall! 🎉**