# DeployGuard Rules

This directory contains all security and best-practice rules for DeployGuard. Rules are organized by category and type (static vs dynamic analysis).

## Rule Categories

| Category | Description | Rule Type |
|----------|-------------|-----------|
| **proxy/** | Proxy deployment issues (CPIMP vulnerabilities) | Static |
| **security/** | Security anti-patterns and access control issues | Static |
| **testing/** | Test coverage and quality issues | Static |
| **config/** | Configuration and deployment settings issues | Static |
| **dynamic/** | On-chain state verification | Dynamic |

---

## Static Rules

Static rules analyze deployment scripts (`*.s.sol`) before they are executed.

### Proxy Rules (`proxy/`)

Rules for detecting CPIMP (Clandestine Proxy In the Middle of Proxy) and related proxy deployment vulnerabilities.

#### `NON_ATOMIC_INIT` - Non-Atomic Proxy Initialization

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **File** | `proxy/non_atomic_init.py` |

Detects proxy contracts deployed without atomic initialization, which creates a window for front-running attacks.

**Triggers when:**
- Proxy deployed with empty initialization data (`""`, `"0x"`, `bytes("")`)
- Deployment and initialization occur in separate transaction boundaries

**Supported deployment methods:**
- `new ERC1967Proxy(impl, "")` - Standard Solidity
- `new ERC1967Proxy{salt: salt}(impl, "")` - Foundry-native CREATE2
- `createX.deployCreate2(salt, bytecode)` - CreateX factory
- Arachnid deterministic deployer (`0x4e59b44847b379578588920ca78fbf26c0b4956c`)

**Why it matters:**
Attackers can monitor the mempool for proxy deployments with empty init data, then front-run the initialization transaction to gain admin control. This is the core CPIMP vulnerability that has affected thousands of contracts.

**References:**
- [CPIMP Attack - Dedaub Blog](https://dedaub.com/blog/the-cpimp-attack-an-insanely-far-reaching-vulnerability-successfully-mitigated/)
- [USPD Rekt](https://rekt.news/uspd-rekt/)
- [Foundry CREATE2 Guide](https://getfoundry.sh/guides/deterministic-deployments-using-create2/)

---

#### `HARDCODED_IMPL` - Hardcoded Implementation Address

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **File** | `proxy/hardcoded_impl.py` |

Detects when implementation addresses are hardcoded in deployment scripts instead of being deployed in the same script.

**Why it matters:**
- Address may be from a different network
- No verification that bytecode exists at that address
- Difficult to audit and maintain

---

#### `MISSING_IMPL_VALIDATION` - Missing Implementation Validation

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **File** | `proxy/missing_impl_validation.py` |

Detects when implementation addresses from external sources are used without validation.

**Why it matters:**
Without validation, a proxy could point to:
- Empty addresses (zero address)
- EOAs (externally owned accounts)
- Addresses without deployed contracts

---

### Security Rules (`security/`)

Rules for detecting security anti-patterns in deployment scripts.

#### `PRIVATE_KEY_ENV` - Private Key in Environment Variable

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **File** | `security/private_key_env.py` |

Detects when deployment scripts load private keys from `.env` files.

**Why it matters:**
- `.env` files can be accidentally committed to git
- Environment variables may be logged or exposed in CI/CD
- No hardware security module (HSM) protection
- Attackers actively scan GitHub for committed `.env` files

**Better alternatives:**
- Hardware wallets (`--ledger`, `--trezor`)
- Encrypted keystore files

---

#### `MISSING_OWNERSHIP_TRANSFER` - Missing Ownership Transfer

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **File** | `security/missing_ownership_transfer.py` |

Detects when Ownable contracts are deployed without transferring ownership to a secure admin.

**Why it matters:**
Leaving ownership with deployer EOA is risky:
- EOA private keys can be compromised
- Single point of failure
- No transparency or governance

**Best practice:** Transfer ownership to multisig, timelock, or DAO governance.

---

#### `DEPLOYER_ADMIN` - Deployer Retains Admin Privileges

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **File** | `security/deployer_admin.py` |

Detects when `msg.sender` (deployer) is explicitly set as admin.

**Patterns detected:**
- `new TransparentUpgradeableProxy(impl, msg.sender, data)`
- `proxy.changeAdmin(msg.sender)`
- `contract.transferOwnership(msg.sender)`

---

#### `UUPS_NO_AUTHORIZE` - UUPS Missing _authorizeUpgrade Override

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **File** | `security/uups_no_authorize.py` |

Warns when UUPS proxies are detected, reminding to verify `_authorizeUpgrade()` override.

**Why it matters:**
Without proper `_authorizeUpgrade()` override with access control, anyone can upgrade the proxy to malicious code.

**Required pattern:**
```solidity
function _authorizeUpgrade(address newImplementation)
    internal
    override
    onlyOwner  // Access control required!
{ }
```

---

#### `UUPS_NO_DISABLE_INIT` - UUPS Missing _disableInitializers

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **File** | `security/uups_no_disable_init.py` |

Warns when UUPS proxies are detected, reminding to call `_disableInitializers()` in constructor.

**Why it matters:**
Without `_disableInitializers()`, attackers can initialize the implementation contract directly, potentially gaining control.

**Required pattern:**
```solidity
constructor() {
    _disableInitializers();
}
```

---

#### `UUPS_UPGRADE_OVERRIDE` - UUPS Override of upgradeToAndCall

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **File** | `security/uups_upgrade_override.py` |

Warns about unsafe overrides of `upgradeToAndCall()` that may break upgrade functionality.

---

#### `UUPS_UNSAFE_OPCODE` - UUPS Uses Delegatecall/Selfdestruct

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **File** | `security/uups_unsafe_opcode.py` |

Warns about `delegatecall` or `selfdestruct` in UUPS implementations.

**Why it matters:**
- `delegatecall`: Can bypass proxy security by delegating to malicious code
- `selfdestruct`: Can destroy the implementation, breaking all proxies

---

### Testing Rules (`testing/`)

Rules for ensuring deployment scripts have proper test coverage.

#### `NO_TEST` - Deployment Script Has No Test

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **File** | `testing/no_test.py` |

Detects deployment scripts without corresponding test files.

**Expected test file locations:**
- `test/{ScriptName}.t.sol`
- `test/{ScriptName}Test.t.sol`
- `test/Deploy.t.sol`

---

#### `TEST_NO_RUN` - Test Doesn't Execute Deployment

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **File** | `testing/test_no_run.py` |

Detects tests that import deployment scripts but don't call `run()`.

**Why it matters:**
Tests that import but don't call `run()` aren't actually testing the deployment.

---

### Config Rules (`config/`)

Rules for deployment configuration issues.

#### `HARDCODED_ADDRESS` - Hardcoded Address Without Environment

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **File** | `config/hardcoded_address.py` |

Detects hardcoded Ethereum addresses that should be configurable.

**Why it matters:**
- Network-specific (can't easily deploy to different networks)
- Hard to maintain (address changes require code changes)
- Difficult to audit (addresses scattered throughout code)

**Best practice:** Use `vm.envAddress()` or configuration files.

**Allowed addresses (not flagged):**
- `0x0000000000000000000000000000000000000000` (zero address)
- `0x000000000000000000000000000000000000dEaD` (burn address)
- `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` (ETH placeholder)

---

## Dynamic Rules

Dynamic rules verify on-chain state of deployed proxy contracts.

### Dynamic Analysis Rules (`dynamic/`)

#### `IMPL_MISMATCH` - Implementation Slot Mismatch

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **File** | `dynamic/impl_mismatch.py` |

Verifies the implementation address in EIP-1967 slot matches expected address.

**Why it matters:**
Implementation mismatches can indicate a CPIMP attack where an attacker front-ran the deployment.

**References:**
- [EIP-1967](https://eips.ethereum.org/EIPS/eip-1967)
- [CPIMP Attack - Dedaub](https://dedaub.com/blog/the-cpimp-attack-an-insanely-far-reaching-vulnerability-successfully-mitigated/)

---

#### `SHADOW_CONTRACT` - Shadow Contract Detection

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **File** | `dynamic/shadow_contract.py` |

Detects when implementation contract contains `DELEGATECALL`, suggesting a malicious middleman proxy.

**Why it matters:**
A shadow contract can intercept all calls and redirect to attacker-controlled code while appearing legitimate.

---

#### `UNINITIALIZED_PROXY` - Uninitialized Proxy

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **File** | `dynamic/uninitialized_proxy.py` |

Detects proxies with empty (zero address) implementation slot.

**Why it matters:**
An uninitialized proxy cannot be used and is vulnerable to initialization front-running.

---

#### `ADMIN_MISMATCH` - Admin Slot Mismatch

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **File** | `dynamic/admin_mismatch.py` |

Verifies the admin address in EIP-1967 admin slot matches expected address.

**Why it matters:**
The admin can upgrade the proxy implementation. An unexpected admin may indicate compromised control.

---

#### `NON_STANDARD_PROXY` - Non-Standard Proxy Pattern

| Property | Value |
|----------|-------|
| **Severity** | INFO |
| **File** | `dynamic/non_standard_proxy.py` |

Detects proxies that don't use standard EIP-1967 storage slots.

**Why it matters:**
Non-standard proxies may use different patterns (EIP-1822, EIP-1167) or custom implementations that require additional verification.

---

## Rule Architecture

### Base Classes

All rules inherit from base classes in `base.py`:

```python
class StaticRule(ABC):
    """Base class for static analysis rules."""
    rule: Rule
    
    @abstractmethod
    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        """Execute rule against parsed script."""
        pass

class DynamicRule(ABC):
    """Base class for dynamic analysis rules."""
    rule: Rule
    
    @abstractmethod
    async def check(
        self,
        proxy_state: ProxyState,
        expected_impl: str,
        expected_admin: str | None = None,
    ) -> list[RuleViolation]:
        """Execute rule against on-chain state."""
        pass
```

### Rule Registry

Rules are registered in `registry.py` and can be filtered by:
- Category
- Severity
- Enabled/disabled status

### Rule Executors

`executors.py` provides executors that run all enabled rules:
- `StaticRuleExecutor` - For static analysis
- `DynamicRuleExecutor` - For dynamic analysis

---

## Adding New Rules

1. Create a new file in the appropriate category directory
2. Implement the rule class inheriting from `StaticRule` or `DynamicRule`
3. Create a `Rule` instance with metadata
4. Instantiate the rule class (auto-registers on import)
5. Export from the category's `__init__.py`
6. Add tests in `tests/`

Example structure:
```python
"""MY_RULE: My Rule Description."""

from deployguard.models.rules import Rule, RuleCategory, RuleViolation, Severity
from deployguard.rules.base import StaticRule

class MyRule(StaticRule):
    def check(self, analysis: ScriptAnalysis) -> list[RuleViolation]:
        # Implementation
        pass

RULE_MY_RULE = Rule(
    rule_id="MY_RULE",
    name="My Rule Name",
    description="What this rule checks",
    severity=Severity.HIGH,
    category=RuleCategory.SECURITY,
    references=["https://..."],
    remediation="How to fix",
)

rule_my_rule = MyRule(RULE_MY_RULE)
```

---

## Rule ID Naming Convention

Rules use descriptive `SCREAMING_SNAKE_CASE` names:

- Self-documenting (no need to look up what `DG-007` means)
- Easy to search in codebase
- No renumbering when rules are added/removed
- Clear category prefixes for related rules (e.g., `UUPS_*`)
