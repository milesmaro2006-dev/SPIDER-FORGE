# Contributing to SpiderForge

First off, thank you for considering contributing to SpiderForge! 🕷️

## Table of Contents

* [Code of Conduct](https://www.google.com/search?q=%23code-of-conduct)
* [How Can I Contribute?](https://www.google.com/search?q=%23how-can-i-contribute)
* [Development Setup](https://www.google.com/search?q=%23development-setup)
* [Coding Standards](https://www.google.com/search?q=%23coding-standards)
* [Commit Guidelines](https://www.google.com/search?q=%23commit-guidelines)
* [Pull Request Process](https://www.google.com/search?q=%23pull-request-process)

---

## Code of Conduct

This project and everyone participating in it is governed by our
[Code of Conduct](https://www.google.com/search?q=CODE_OF_CONDUCT.md). By participating, you are expected to
uphold this code.

---

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating bug reports, please check the issue tracker to avoid duplicates.
When you create a bug report, include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples** (commands, URLs, configs)
* **Describe the behavior you observed and what you expected**
* **Include screenshots or logs if relevant**
* **Note your environment**: OS, Python version, SpiderForge version

### 💡 Suggesting Features

Feature suggestions are welcome. When suggesting a feature:

* **Use a clear and descriptive title**
* **Provide a step-by-step description of the suggested feature**
* **Explain why this feature would be useful**
* **List some examples of how it would work**

### 🔧 Pull Requests

* Fill in the required template
* Follow the coding standards below
* Include tests for new features
* Update documentation as needed

---

## Development Setup

### 1. Fork and clone

```bash
git clone https://github.com/YOUR-USERNAME/spider-forge.git
cd spider-forge

```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate        # Windows

```

### 3. Install in development mode

```bash
pip install -e ".[dev]"

```

### 4. Run the test suite

```bash
pytest

```

### 5. Run the linter and type checker

```bash
ruff check .
ruff format .
mypy spiderforge/

```

### 6. Run the tool locally

```bash
python -m spiderforge.cli.main

```

---

## Coding Standards

### Python Style

* Follow PEP 8
* Line length: 100 characters (enforced by Ruff)
* Use type hints everywhere possible
* Prefer f-strings over `.format()`
* Use `pathlib` over `os.path` where reasonable

### Naming Conventions

| Type | Convention | Example |
| --- | --- | --- |
| Modules | `snake_case` | `sql_scanner.py` |
| Classes | `PascalCase` | `ScanEngine` |
| Functions | `snake_case` | `run_scan()` |
| Constants | `UPPER_SNAKE_CASE` | `MAX_RETRIES` |
| Private | `_leading_underscore` | `_helper()` |

### Docstrings

Use Google-style docstrings:

```python
def scan_target(url: str, timeout: float = 10.0) -> dict:
    """Run a security scan against the given URL.

    Args:
        url: Target URL to scan.
        timeout: Request timeout in seconds.

    Returns:
        Dictionary containing findings and metadata.

    Raises:
        httpx.RequestError: If the target is unreachable.
    """

```

### Async Code

* Prefer `httpx.AsyncClient` over `requests`
* Reuse a single client across scanners
* Always handle `httpx.RequestError` gracefully

---

## Commit Guidelines

We follow Conventional Commits:

```text
<type>(<scope>): <description>

[optional body]

[optional footer]

```

### Types

| Type | Purpose |
| --- | --- |
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting (no code change) |
| `refactor` | Code restructure (no behavior change) |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `chore` | Build/tooling changes |
| `ci` | CI/CD changes |

### Examples

```text
feat(scanners): add SSRF detection module
fix(cli): handle missing config file gracefully
docs(readme): update installation instructions
test(sqli): add unit tests for error patterns

```

---

## Pull Request Process

* Update the `README.md` if you change behavior
* Update the `CHANGELOG.md` under `[Unreleased]`
* Add tests for new functionality
* Ensure all tests pass: `pytest`
* Ensure linting passes: `ruff check .`
* Ensure type checking passes: `mypy spiderforge/`
* Fill in the PR template completely
* Link related issues in the description

### PR Title Format

Use the same convention as commits:

```text
feat(scanners): add SSRF detection
fix(cli): correct argument parsing for --target

```

### Review Process

* Maintainers will review your PR as soon as possible
* Address review comments promptly
* Keep the PR focused on a single change
* Rebase on `main` if needed

---

## Questions?

Feel free to open an issue or reach out to the maintainer:

Amr Shaban — [@milesmaro2006-dev](https://www.google.com/search?q=https://github.com/milesmaro2006-dev)

Thank you for contributing! 🕷️
