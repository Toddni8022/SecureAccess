# Contributing to SecureAccess

Thank you for your interest in contributing to SecureAccess! This document outlines how to get involved, our development workflow, and the standards we follow.

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) Code of Conduct. By participating, you agree to uphold a welcoming and respectful environment for everyone.

---

## How to Contribute

### Reporting Bugs

1. Search [existing issues](https://github.com/Toddni8022/SecureAccess/issues) to avoid duplicates.
2. Open a new issue using the **Bug Report** template.
3. Include:
   - Operating system and Python version
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant log output or screenshots

### Suggesting Features

1. Open a [Feature Request](https://github.com/Toddni8022/SecureAccess/issues/new) issue.
2. Describe the use case and why it benefits security teams.
3. If possible, sketch a proposed API or UI design.

### Contributing Code

1. **Fork** the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/SecureAccess.git
   cd SecureAccess
   ```

2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/my-feature-name
   # or
   git checkout -b fix/issue-123-description
   ```

3. **Set up your development environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   make install
   ```

4. **Make your changes.** Keep commits small and focused.

5. **Run tests and linting before pushing:**
   ```bash
   make test
   make lint
   make typecheck
   ```

6. **Commit** with a clear, conventional message (see [Commit Conventions](#commit-message-conventions)).

7. **Push** your branch and open a **Pull Request** against `main`.

---

## Development Setup

### Prerequisites

- Python 3.10 or later
- `make` (optional, for `Makefile` targets)
- tkinter (see [deployment.md](docs/deployment.md) for platform-specific instructions)

### Install All Dev Dependencies

```bash
make install
# Equivalent to:
pip install -r requirements.txt
pip install pytest pytest-cov ruff mypy pytest-mock
```

### Running the Application Locally

```bash
make run
# or
python app.py
```

---

## Running Tests

```bash
# Run all tests
make test

# Run tests with verbose output
pytest tests/ -v

# Run a specific test file
pytest tests/test_database.py -v

# Run a specific test
pytest tests/test_auth.py::TestPasswordPolicy::test_valid_password_passes -v

# Run tests excluding GUI tests (for CI)
pytest tests/ -v -k "not gui"

# Run with coverage report
pytest tests/ --cov=src --cov=database --cov=connectors --cov-report=term-missing
```

---

## Code Style

### Linting — Ruff

We use [Ruff](https://github.com/astral-sh/ruff) for fast Python linting and import sorting.

```bash
make lint
# or
ruff check src/ tests/ database.py connectors.py --ignore E501
```

Fix auto-fixable issues:
```bash
ruff check src/ tests/ --fix
```

### Type Checking — mypy

```bash
make typecheck
# or
mypy src/ --ignore-missing-imports
```

### Code Style Rules

- **Line length:** 120 characters (configured in `pyproject.toml`)
- **Quotes:** Double quotes for strings
- **Imports:** Sorted by `ruff` (isort-compatible)
- **Type hints:** Required for all new functions and methods
- **Docstrings:** Required for public modules, classes, and functions
- **Comments:** Explain *why*, not *what*

---

## Commit Message Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `test` | Adding or updating tests |
| `refactor` | Code change without feature or fix |
| `style` | Formatting, whitespace |
| `chore` | Build process, CI, dependency updates |
| `security` | Security fix |

### Examples

```
feat(connectors): add Google Workspace connector

Implements the Google Directory API connector for user provisioning
in Google Workspace organizations.

Closes #42
```

```
fix(database): handle missing password_policy row gracefully

If no policy row exists, get_password_policy() now returns None
instead of raising an IndexError.

Fixes #17
```

---

## Pull Request Checklist

Before submitting your PR, please verify:

- [ ] All existing tests pass (`make test`)
- [ ] New code is covered by tests
- [ ] Linting passes (`make lint`)
- [ ] Type checking passes (`make typecheck`)
- [ ] Docstrings added for new public functions/classes
- [ ] `CHANGELOG.md` updated with a brief description of the change
- [ ] No secrets or credentials committed
- [ ] PR description explains *what* and *why*

---

## Project Structure

See [docs/architecture.md](docs/architecture.md) for the full directory layout and architectural overview.

Key files:
- `app.py` — Main GUI application (CustomTkinter)
- `database.py` — SQLite database layer
- `connectors.py` — External system integrations
- `src/secure_access/` — Importable package modules
- `tests/` — Pytest test suite

---

## Adding a New Connector

1. Subclass `BaseConnector` in `connectors.py` — see [docs/connectors.md](docs/connectors.md) for a complete guide.
2. Register the connector in `CONNECTORS`.
3. Add connector tests in `tests/test_connectors.py`.
4. Document the connector in `docs/connectors.md`.

---

## Questions?

Open a [Discussion](https://github.com/Toddni8022/SecureAccess/discussions) or reach out via an [Issue](https://github.com/Toddni8022/SecureAccess/issues).
