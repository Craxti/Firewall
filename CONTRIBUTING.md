# Guidelines for Contributing to the Firewall Project

Thank you for considering contributing to the Firewall Project! Here are some guidelines to help you through the process.

## Preparing the environment

1. Fork the project
2. Clone the repository: `git clone https://github.com/YOUR_USERNAME/firewall.git`
3. Create a virtual environment: `python -m venv venv`
4. Activate the virtual environment:
- Windows: `venv\Scripts\activate`
- Linux/Mac: `source venv/bin/activate`
5. Install dependencies: `pip install -r requirements.txt`
6. Install the project in development mode: `pip install -e .`

## Testing

Before submitting a Pull Request, please make sure all tests pass:

```bash
pytest tests/
```

Also check your code for style compliance with flake8:

```bash
flake8 firewall/ tests/
```

## Pull Requests

1. Create a new branch for your changes: `git checkout -b feature/my-feature`
2. Make your changes and commit them: `git commit -am "Added new feature"`
3. Push your changes to your fork: `git push origin feature/my-feature`
4. Create a Pull Request to the main repository

## Code Guidelines

- Follow PEP 8 style
- Write clear comments in English
- Add tests for new functionality
- Update documentation if necessary

## Reporting Bugs

If you find a bug, please create an issue on GitHub with the following information:

- Python version
- Operating system
- Firewall version
- Steps to reproduce the bug
- Expected and actual behavior

## Suggestions for Enhancements

Suggestions for enhancements are also welcome! Create an issue with the "enhancement" tag and describe your idea.