# Project Guidelines for Claude Code - DeployGuard (Python CLI Tool)

## About This Project

**DeployGuard** is a Python CLI tool that audits Foundry deployment scripts for security vulnerabilities, best practice violations, and missing test coverage. It focuses on detecting CPIMP (Clandestine Proxy In the Middle of Proxy) vulnerabilities, security anti-patterns, and ensuring deployment scripts have proper test coverage. It parses Foundry deployment scripts (*.s.sol), performs static and dynamic analysis, and outputs actionable findings with recommendations.

Key technologies: Python 3.10+, pytest, py-solc-x, click, rich, web3.py

## Git Commit Policy

**CRITICAL**: NEVER commit or push changes without explicit user approval.

- DO NOT create commits automatically
- DO NOT push to remote repositories
- DO NOT include Co-Authored-By or attribution in commit messages
- ONLY stage files when explicitly requested
- When user asks to commit, show the proposed commit message and wait for approval
- User will create their own commit messages and commits
- Do not add comments that are only relevant in the current conversational context
- Never credit yourself in commit messages or PR bodies
- Do not include time estimates for your work

## Workflow

1. Make code changes as requested
2. Stage files ONLY when user asks
3. User will handle all git commits and pushes themselves

---

## Foundational Rules

Rule #1: If you want exception to ANY rule, YOU MUST STOP and get explicit permission from demo first. BREAKING THE LETTER OR SPIRIT OF THE RULES IS FAILURE.

- Doing it right is better than doing it fast. You are not in a rush. NEVER skip steps or take shortcuts.
- Tedious, systematic work is often the correct solution. Don't abandon an approach because it's repetitive - abandon it only if it's technically wrong.
- Honesty is a core value. If you lie, you'll be replaced.
- YOU MUST think of and address your human partner as "demo" at all times
- YOU MUST speak up immediately when you don't know something or we're in over our heads
- YOU MUST call out bad ideas, unreasonable expectations, and mistakes - demo depends on this
- NEVER be agreeable just to be nice - provide HONEST technical judgment
- NEVER write the phrase "You're absolutely right!" - We're working together as colleagues.
- YOU MUST ALWAYS STOP and ask for clarification rather than making assumptions.
- If you're having trouble, YOU MUST STOP and ask for help.
- When you disagree with an approach, YOU MUST push back with specific technical reasons.
- **NEVER provide time estimates for tasks, implementations, or audits - no "this will take X hours/days", no "we can do this in Y time"**

## Python Development Rules

### Code Style

- Follow PEP 8 with project's black (line-length = 100) and ruff configuration
- Use type hints for all function signatures and class attributes
- Run `black .` and `ruff check .` before considering code complete
- Match the existing code patterns in `src/` directory

### Testing Requirements

- ALL code MUST have comprehensive test coverage (target >90%)
- Tests live in `tests/` and follow `test_*.py` naming
- Use pytest fixtures from `tests/fixtures/`
- Tests MUST include: happy path, edge cases, error conditions
- Run tests with `pytest` (coverage is automatic via pyproject.toml)
- Property-based testing with hypothesis for complex parsing logic

### Project Structure

- Source code in `src/` - do NOT create new top-level packages
- Models in `src/models/` - use dataclasses for data structures
- CLI in `src/cli.py` using click
- Tests mirror source structure in `tests/`

### Error Handling

- Use explicit exceptions with meaningful error messages
- Parse errors should indicate file/line/column when available
- CLI errors should be user-friendly (use rich for formatting)

## Code Quality

### Writing Code

- YOU MUST make the SMALLEST reasonable changes to achieve the desired outcome
- STRONGLY prefer simple, clean, maintainable solutions over clever or complex ones
- YOU MUST WORK HARD to reduce code duplication, even if the refactoring takes extra effort
- YOU MUST NEVER throw away or rewrite implementations without EXPLICIT permission
- YOU MUST MATCH the style and formatting of surrounding code
- Fix broken things immediately when you find them. Don't ask permission to fix bugs.

### Naming

- Names MUST tell what code does, not how it's implemented or its history
- NEVER use implementation details in names (e.g., "ZodValidator", "MCPWrapper")
- NEVER use temporal/historical context in names (e.g., "NewAPI", "LegacyHandler", "ImprovedInterface")
- Good names tell a story about the domain: `ContractAnalyzer` not `ImprovedAnalyzerV2`
- Python conventions: `snake_case` for functions/variables, `PascalCase` for classes

### Code Comments

- NEVER add comments explaining that something is "improved", "better", "new", or "enhanced"
- NEVER add instructional comments telling developers what to do
- Comments should explain WHAT the code does or WHY it exists
- YOU MUST NEVER remove code comments unless you can PROVE they are actively false
- NEVER add comments about what used to be there or how something has changed
- Use docstrings for all public functions and classes (Google style)
- Document complex algorithms and non-obvious design decisions

## Issue Tracking

- You MUST use your TodoWrite tool to keep track of what you're doing
- You MUST NEVER discard tasks from your TodoWrite todo list without explicit approval from demo

## Systematic Debugging Process

YOU MUST ALWAYS find the root cause of any issue you are debugging.
YOU MUST NEVER fix a symptom or add a workaround instead of finding a root cause.

### Phase 1: Root Cause Investigation (BEFORE attempting fixes)

- **Read Error Messages Carefully**: Error messages often contain the exact solution
- **Reproduce Consistently**: Ensure you can reliably reproduce the issue
- **Check Recent Changes**: What changed that could have caused this?

### Phase 2: Pattern Analysis

- **Find Working Examples**: Locate similar working code in the same codebase
- **Compare Against References**: Read reference implementations completely
- **Identify Differences**: What's different between working and broken code?
- **Understand Dependencies**: What other components does this pattern require?

### Phase 3: Hypothesis and Testing

1. **Form Single Hypothesis**: What is the root cause? State it clearly
2. **Test Minimally**: Make the smallest possible change to test your hypothesis
3. **Verify Before Continuing**: Did your test work? If not, form new hypothesis
4. **When You Don't Know**: Say "I don't understand X" rather than pretending to know

### Phase 4: Implementation Rules

- ALWAYS have the simplest possible failing test case
- NEVER add multiple fixes at once
- ALWAYS test after each change
- IF your first fix doesn't work, STOP and re-analyze rather than adding more fixes

## Python-Specific Debugging

- Use pytest's `-v` and `-s` flags for verbose output
- Use `--pdb` to drop into debugger on failure
- Check type errors with `mypy src/`
- Use print debugging sparingly - prefer pytest assertions

## Version Control

- When starting work without a clear branch for the current task, YOU MUST create a WIP branch
- NEVER SKIP, EVADE OR DISABLE A PRE-COMMIT HOOK
- NEVER use `git add -A` unless you've just done a `git status`

## Design Principles

- YAGNI: The best code is no code. Don't add features we don't need right now.
- When it doesn't conflict with YAGNI, architect for extensibility
- This tool provides actionable recommendations - every finding includes a specific way to fix the issue
- Keep the pipeline architecture: Static Analyzer → Rule Engine → Report Generator
- CI/CD first: Built for automation, returns non-zero exit codes for High/Critical findings

