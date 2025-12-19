# Contributing to DeployGuard

Thank you for your interest in contributing to DeployGuard!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/0xstormblessed/deployguard.git
   cd deployguard
   ```

2. Install in development mode with dev dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

3. Verify installation:
   ```bash
   deployguard --version
   pytest
   ```

## Running Tests

```bash
# Run all tests with coverage
pytest

# Run specific test file
pytest tests/test_cli.py

# Run with verbose output
pytest -v

# Skip slow tests (requires solc)
pytest -m "not slow"
```

## Code Style

This project uses:
- **black** for code formatting (line-length = 100)
- **ruff** for linting
- **mypy** for type checking

Before submitting a PR:
```bash
black .
ruff check .
mypy src/
```

## Type Hints

All functions must have type hints:
```python
def analyze_script(path: Path, fail_fast: bool = False) -> AnalysisReport:
    ...
```

## Adding New Rules

1. Create a new file in the appropriate category under `src/deployguard/rules/`:
   - `proxy/` - Proxy deployment issues
   - `security/` - Security anti-patterns
   - `testing/` - Test coverage issues
   - `config/` - Configuration issues
   - `dynamic/` - On-chain verification

2. Inherit from `StaticRule` or `DynamicRule`

3. Register the rule by instantiating it (auto-registers on import)

4. Export from the category's `__init__.py`

5. Add tests in `tests/`

See `src/deployguard/rules/README.md` for detailed documentation.

## Pull Request Process

1. Create a feature branch from `master`
2. Make your changes with tests
3. Ensure all tests pass and coverage remains above 80%
4. Run code formatting and linting
5. Submit a PR with a clear description

## Reporting Issues

When reporting bugs, please include:
- DeployGuard version (`deployguard --version`)
- Python version
- Operating system
- Minimal reproduction steps
- Error messages and stack traces

## Questions?

Open an issue on GitHub for questions or discussions.
