# DeployGuard

**DeployGuard** is a CLI tool for auditing Foundry deployment scripts for security vulnerabilities, best practice violations, and missing test coverage. It focuses on detecting CPIMP (Clandestine Proxy In the Middle of Proxy) vulnerabilities and other security anti-patterns.

## ⚠️ Important Notes

**DeployGuard is an opinionated tool** based on security experience and best practices. The rules, recommendations, and best practices enforced by DeployGuard reflect real-world security lessons learned from auditing smart contract deployments. While these opinions are grounded in practical security experience, teams may have different approaches that are equally valid for their specific use cases.

**DeployGuard is NOT a security guarantee.** This tool helps development teams follow best practices and established guidelines for smart contract deployments. It is designed to catch common anti-patterns and provide actionable recommendations, but:

- Does **not** replace professional security audits
- Does **not** guarantee the absence of vulnerabilities
- May produce false positives or miss certain issues
- Should be used as **one layer** of a comprehensive security strategy

## Installation

### From PyPI

```bash
pip install deployguard
```

### From Source

```bash
git clone https://github.com/0xstormblessed/deployguard.git
cd deployguard
pip install -e .
```

### Requirements

- Python 3.10+
- Foundry (for Solidity compilation)

## Quick Start

```bash
# Audit all deployment scripts in a directory
deployguard audit ./script

# Audit a single deployment script
deployguard audit script/Deploy.s.sol

# Verify a deployed proxy on-chain
deployguard verify 0x1234...5678 \
  --rpc https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  --expected 0xABCD...EF01

# Check test coverage for deployment scripts
deployguard check

# List all available rules
deployguard rules
```

## Commands

### `audit` - Static Analysis

Analyze deployment scripts for security vulnerabilities.

```bash
# Audit a directory (recursive)
deployguard audit ./script

# Audit with JSON output (for CI/CD)
deployguard audit ./script -o json

# Filter files with glob patterns
deployguard audit . --include '**/*.s.sol' --exclude '**/mock/**'

# Stop on first error
deployguard audit ./script --fail-fast
```

**Options:**
| Option | Description |
|--------|-------------|
| `-o, --output` | Output format: `console`, `json`, `sarif` |
| `--include` | Glob patterns to include |
| `--exclude` | Glob patterns to exclude |
| `--no-gitignore` | Don't respect .gitignore patterns |
| `--fail-fast` | Stop on first analysis error |

**Exit Codes:**
- `0` - No critical/high findings
- `1` - Critical or high severity findings detected

### `verify` - Dynamic Analysis

Verify a deployed proxy matches the expected implementation address.

```bash
deployguard verify 0xProxyAddress \
  --rpc https://eth-mainnet.g.alchemy.com/v2/KEY \
  --expected 0xExpectedImpl \
  --admin 0xExpectedAdmin
```

**Example: Detecting the USPD CPIMP Attack**

This example verifies the USPD proxy on Ethereum mainnet. The proxy was exploited via a CPIMP attack where an attacker front-ran the initialization:

```bash
# Requires an Ethereum mainnet RPC endpoint
deployguard verify 0x1346B4d6867a382B02b19A8D131D9b96b18585f2 \
  --rpc https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  --expected 0x93486b98e64de344d6a5a322a4bd80e65d83e5ca
```

This will detect `IMPL_MISMATCH` because the on-chain implementation differs from the intended `cUSPDToken` implementation - evidence of the CPIMP attack.

**Options:**
| Option | Description |
|--------|-------------|
| `--rpc` | RPC endpoint URL (required) |
| `--expected` | Expected implementation address (required) |
| `--admin` | Expected admin address (optional) |
| `-o, --output` | Output format: `console`, `json` |

### `check` - Test Coverage

Check that deployment scripts have corresponding test coverage.

```bash
# Check current directory
deployguard check

# Check specific project
deployguard check ./my-project

# JSON output
deployguard check -o json
```

### `rules` - List Rules

List all available security rules.

```bash
# List all rules
deployguard rules

# Filter by category
deployguard rules --category proxy

# Filter by severity
deployguard rules --severity critical

# JSON output
deployguard rules -o json
```

## Rule Categories

### Proxy Rules (CPIMP Detection)

| Rule | Severity | Description |
|------|----------|-------------|
| `NON_ATOMIC_INIT` | Critical | Non-atomic proxy initialization allows front-running |
| `HARDCODED_IMPL` | Medium | Hardcoded implementation address |
| `MISSING_IMPL_VALIDATION` | Medium | Missing implementation address validation |

### Security Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `PRIVATE_KEY_ENV` | High | Private key loaded from environment variable |
| `MISSING_OWNERSHIP_TRANSFER` | Medium | Ownership not transferred after deployment |
| `DEPLOYER_ADMIN` | Medium | Deployer retains admin privileges |
| `UUPS_NO_AUTHORIZE` | Critical | UUPS missing `_authorizeUpgrade` override |
| `UUPS_NO_DISABLE_INIT` | High | UUPS missing `_disableInitializers` |
| `UUPS_UPGRADE_OVERRIDE` | Medium | UUPS override of `upgradeToAndCall` |
| `UUPS_UNSAFE_OPCODE` | High | UUPS uses delegatecall/selfdestruct |

### Testing Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `NO_TEST` | Medium | Deployment script has no test coverage |
| `TEST_NO_RUN` | Low | Test doesn't call `run()` function |

### Dynamic Rules (On-Chain Verification)

| Rule | Severity | Description |
|------|----------|-------------|
| `IMPL_MISMATCH` | Critical | On-chain implementation doesn't match expected |
| `SHADOW_CONTRACT` | Critical | Proxy delegates to unexpected contract |
| `UNINITIALIZED_PROXY` | Critical | Proxy is not initialized |
| `ADMIN_MISMATCH` | High | Admin slot doesn't match expected |
| `NON_STANDARD_PROXY` | Medium | Non-standard proxy pattern detected |

## CI/CD Integration

### GitHub Actions

```yaml
name: DeployGuard Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1

      - name: Install DeployGuard
        run: pip install deployguard

      - name: Run Audit
        run: deployguard audit ./script -o json > audit-report.json

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: audit-report.json
```

### Exit Code Usage

```bash
# In CI scripts, check exit code
deployguard audit ./script
if [ $? -ne 0 ]; then
  echo "Security issues found!"
  exit 1
fi
```

## Example Output

```
================================================================================
DEPLOYGUARD ANALYSIS REPORT
================================================================================

================================================================================
FILE: script/Deploy.s.sol
================================================================================

[CRITICAL] NON_ATOMIC_INIT: Non-Atomic Proxy Initialization
  Location: line 45 in Deploy.s.sol
  → ERC1967Proxy proxy = new ERC1967Proxy(address(impl), "");
  Description: ERC1967Proxy deployed with empty initialization data...

  Warning Why this matters:
  This is vulnerable to a CPIMP (Clandestine Proxy In the Middle of Proxy) attack.
  Attackers monitor mempools for proxy deployments with empty init data, then
  front-run the initialization transaction to gain admin control. Dedaub identified
  CPIMP as affecting thousands of contracts across multiple chains.

  Related Exploits:
    - https://rekt.news/uspd-rekt/

  Documentation:
    - https://dedaub.com/blog/the-cpimp-attack-an-insanely-far-reaching-vulnerability-successfully-mitigated/

  Recommendation: Pass initialization data to the proxy constructor...

================================================================================
SUMMARY
================================================================================
Files scanned: 5
Files with findings: 1
Total findings: 1 (1 critical, 0 high, 0 medium, 0 low, 0 info)
Status: FAILED
================================================================================
```

## License

DeployGuard is licensed under the **Apache License 2.0**.

- **Free for all use** - personal, commercial, and open source projects
- **Commercial license required** - if offering DeployGuard as a SaaS or managed service

For commercial licensing inquiries, contact the project maintainers. See [LICENSE](LICENSE) for full text.
