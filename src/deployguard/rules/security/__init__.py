"""Security-related rules for deployment scripts."""

from deployguard.rules.registry import registry
from deployguard.rules.security.private_key_env import RULE_PRIVATE_KEY_ENV, rule_private_key_env
from deployguard.rules.security.missing_ownership_transfer import RULE_MISSING_OWNERSHIP_TRANSFER, rule_missing_ownership_transfer
from deployguard.rules.security.deployer_admin import RULE_DEPLOYER_ADMIN, rule_deployer_admin
from deployguard.rules.security.uups_no_authorize import RULE_UUPS_NO_AUTHORIZE, rule_uups_no_authorize
from deployguard.rules.security.uups_no_disable_init import RULE_UUPS_NO_DISABLE_INIT, rule_uups_no_disable_init
from deployguard.rules.security.uups_upgrade_override import RULE_UUPS_UPGRADE_OVERRIDE, rule_uups_upgrade_override
from deployguard.rules.security.uups_unsafe_opcode import RULE_UUPS_UNSAFE_OPCODE, rule_uups_unsafe_opcode

# Register all security rules
registry.register_static(rule_private_key_env)
registry.register_static(rule_missing_ownership_transfer)
registry.register_static(rule_deployer_admin)
registry.register_static(rule_uups_no_authorize)
registry.register_static(rule_uups_no_disable_init)
registry.register_static(rule_uups_upgrade_override)
registry.register_static(rule_uups_unsafe_opcode)

__all__ = [
    "RULE_PRIVATE_KEY_ENV",
    "RULE_MISSING_OWNERSHIP_TRANSFER",
    "RULE_DEPLOYER_ADMIN",
    "RULE_UUPS_NO_AUTHORIZE",
    "RULE_UUPS_NO_DISABLE_INIT",
    "RULE_UUPS_UPGRADE_OVERRIDE",
    "RULE_UUPS_UNSAFE_OPCODE",
    "rule_private_key_env",
    "rule_missing_ownership_transfer",
    "rule_deployer_admin",
    "rule_uups_no_authorize",
    "rule_uups_no_disable_init",
    "rule_uups_upgrade_override",
    "rule_uups_unsafe_opcode",
]
