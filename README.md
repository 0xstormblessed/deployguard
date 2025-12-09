# DeployGuard

**DeployGuard** is a CLI tool for checking Foundry deployment scripts against a set of best practices. It aims to help detect security vulnerabilities, best practice violations, and missing test coverage in smart contract deployment scripts.

## ⚠️ Important Notes

**DeployGuard is an opinionated tool** based on security experience and best practices. The rules, recommendations, and best practices enforced by DeployGuard reflect real-world security lessons learned from auditing smart contract deployments. While these opinions are grounded in practical security experience, teams may have different approaches that are equally valid for their specific use cases.

**DeployGuard is NOT a security guarantee.** This tool helps development teams follow best practices and established guidelines for smart contract deployments. It is designed to catch common anti-patterns and provide actionable recommendations, but:

- It does **not** replace professional security audits
- It does **not** guarantee the absence of vulnerabilities
- It may produce false positives or miss certain issues
- It should be used as **one layer** of a comprehensive security strategy

Always combine automated tooling with manual code review, professional audits, and thorough testing before deploying to mainnet.

## Quick Start

```bash
# Install
pip install deployguard

# Audit a deployment script
deployguard audit script/Deploy.s.sol

# Verify a deployed proxy
deployguard verify 0x1234...5678 \
  --rpc https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  --expected 0xABCD...EF01
```

## Core Capabilities

1. **CPIMP Detection**: Identifies non-atomic proxy initialization vulnerabilities
2. **Security Anti-Patterns**: Flags private key exposure risks and missing ownership transfers
3. **Test Coverage**: Ensures deployment scripts have corresponding test coverage
4. **Dynamic Verification**: Verifies deployed proxies match expected implementation addresses

## Documentation

See the [specs/](specs/) directory for complete technical specifications:

- [Architecture Overview](specs/00_architecture_overview.md)
- [Data Models](specs/01_data_models.md)
- [CLI Interface](specs/05_cli_interface.md)
- [Full Specs Index](specs/README.md)

## License

DeployGuard is licensed under the **Apache License 2.0**.

### Free Use (Apache 2.0)

You may use DeployGuard **free of charge** for:
- ✅ Personal projects
- ✅ Commercial projects
- ✅ Open source projects
- ✅ Internal CI/CD pipelines
- ✅ Your own smart contract deployments
- ✅ Integrating into your own tools

### Commercial License Required

A **commercial license is required** if you are:
- ⚠️ Offering DeployGuard as a SaaS service
- ⚠️ Hosting DeployGuard as a managed service for customers
- ⚠️ Integrating DeployGuard into a commercial security platform
- ⚠️ Charging customers for DeployGuard analysis capabilities

**In summary**: Free for all projects, but commercial license required if you're selling DeployGuard analysis as a service.

For commercial licensing inquiries, please contact the project maintainers.

See [LICENSE](LICENSE) for full license text.

