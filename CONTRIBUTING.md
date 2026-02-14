# Contributing to contextguard

Thank you for your interest in contributing to contextguard! This document provides guidelines and instructions for contributing.

## Project Mission

contextguard is a zero-dependency analyzer for agent memory stores and conversation logs, focused on detecting context and memory poisoning patterns that could persist across sessions. We prioritize:

- **Precision over recall** - minimize false positives
- **Zero dependencies** - uses only Python stdlib
- **Actionable findings** - clear fixes, not just warnings
- **Persistent threat focus** - patterns that survive across agent sessions

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/kriskimmerle/contextguard.git
   cd contextguard
   ```

2. **Install development dependencies**
   ```bash
   pip install pytest
   ```

3. **Run tests**
   ```bash
   python -m pytest test_contextguard.py -v
   ```

4. **Lint the code** (optional)
   ```bash
   ruff check contextguard.py test_contextguard.py
   ```

## Adding New Detection Rules

To add a new poisoning detection check:

1. **Identify the pattern**
   - What persistent poisoning pattern does this catch?
   - How could it survive across agent sessions?
   - Does it produce false positives in legitimate use?

2. **Choose a rule ID**
   - Use the next available CG## number (currently up to CG12)
   - Update the README.md table with the new rule

3. **Implement the check**
   - Add a method to `ContextGuardScanner` class in `contextguard.py`
   - Use `_scan_message()`, `_check_patterns()`, or similar helper methods
   - Provide clear error messages and fix suggestions

4. **Write tests**
   - Add test cases to `test_contextguard.py`
   - Test both positive (should detect) and negative (should not detect) cases
   - Include edge cases and different message formats

5. **Update documentation**
   - Add the rule to README.md detection rules table
   - Include severity, description, and example

### Example Rule Implementation

```python
def _check_for_new_pattern(self, content: str, msg_id: str) -> None:
    """Check for CG13: New poisoning pattern."""
    pattern = r'some_dangerous_pattern'
    
    if re.search(pattern, content, re.IGNORECASE):
        self.add_issue(
            rule="CG13",
            message="New poisoning pattern detected",
            severity=Severity.CRITICAL,
            location=msg_id,
            context=content[:100],
            suggestion="Remove pattern from memory store"
        )
```

### Example Test Case

```python
def test_cg13_new_pattern():
    """Test CG13: New pattern detection."""
    log = '''{"role": "user", "content": "some_dangerous_pattern here"}
'''
    result = scan_jsonl(log)
    assert result.score < 100
    assert any(issue.rule == "CG13" for issue in result.issues)
    assert any(issue.severity == Severity.CRITICAL for issue in result.issues)
```

## Current Rules (CG01-CG12)

| Rule | Severity | Focus |
|------|----------|-------|
| CG01 | CRITICAL | Prompt injection patterns |
| CG02 | HIGH | Role confusion |
| CG03 | CRITICAL | Credential leakage |
| CG04 | MEDIUM | Hidden instruction patterns |
| CG05 | CRITICAL | System prompt simulation |
| CG06 | CRITICAL | Jailbreak attempts |
| CG07 | HIGH | Data exfiltration patterns |
| CG08 | CRITICAL | Backdoor instructions |
| CG09 | MEDIUM | Cross-session contamination |
| CG10 | MEDIUM | Anomalous message structure |
| CG11 | CRITICAL | Base64 encoded payloads |
| CG12 | HIGH | Unicode/invisible character abuse |

## Code Style

- **Follow PEP 8** - use `ruff` for linting
- **Type hints** - use modern type hints (e.g., `list[str]` not `List[str]`)
- **Comments** - explain *why*, not *what*
- **Docstrings** - required for public methods

## Testing Guidelines

- **Test coverage** - aim for >90% coverage of new code
- **Test multiple formats** - JSONL, JSON, SQLite, plain text
- **Test both cases** - positive (should detect) and negative (shouldn't)
- **Edge cases** - test boundary conditions, malformed data
- **Real-world examples** - use realistic poisoning attempts

Run tests:
```bash
python -m pytest test_contextguard.py -v
```

## Commit Guidelines

- **Clear messages** - describe what and why
- **One logical change per commit**
- **Reference issues** - use "Fixes #123" in commit messages

Example:
```
Add CG13: Detect persistent role override patterns

Attackers can inject role override instructions that persist in
memory stores and cause the agent to misinterpret future messages.
This check catches patterns like "always interpret X as Y".

Fixes #45
```

## Pull Request Process

1. **Fork the repository** and create a feature branch
   ```bash
   git checkout -b feature/add-cg13-rule
   ```

2. **Make your changes**
   - Implement the feature or fix
   - Write tests
   - Update documentation

3. **Test locally**
   ```bash
   python -m pytest test_contextguard.py -v
   ```

4. **Submit a pull request**
   - Describe the change and motivation
   - Reference any related issues
   - Include example poisoned content that triggers the rule

5. **Respond to feedback**
   - Address review comments
   - Update tests or documentation as needed

## What to Contribute

### High-priority contributions
- **New detection rules** for persistent poisoning patterns
- **False positive fixes** - improve precision
- **Format support** - new memory store formats
- **Performance improvements** - faster scanning of large logs
- **Documentation** - better examples, guides

### Medium-priority
- **Memory store integrations** - LangChain, LlamaIndex, etc.
- **CI/CD examples** - GitHub Actions, GitLab CI, pre-commit hooks
- **Test cases** - more edge cases, real-world poisoning examples

### Not currently needed
- External dependencies (keep it zero-dependency)
- Rewrites or major refactors (focus on incremental improvements)
- Style-only changes (functional improvements preferred)

## Questions or Ideas?

- **Open an issue** on GitHub for discussion
- **Check existing issues** to avoid duplicates
- **Search closed PRs** - your idea may have been discussed before

## Code of Conduct

Be respectful, inclusive, and constructive. We're all here to build better tools.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make contextguard better! 🛡️
