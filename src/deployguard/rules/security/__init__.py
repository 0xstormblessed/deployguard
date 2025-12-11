"""Security-related rules for deployment scripts."""

from deployguard.rules.registry import registry
from deployguard.rules.security.dg005_private_key import RULE_DG_005, rule_dg005
from deployguard.rules.security.dg006_ownership import RULE_DG_006, rule_dg006
from deployguard.rules.security.dg007_deployer_admin import RULE_DG_007, rule_dg007
from deployguard.rules.security.dg008_uups_authorize import RULE_DG_008, rule_dg008
from deployguard.rules.security.dg009_uups_disable_init import RULE_DG_009, rule_dg009
from deployguard.rules.security.dg010_uups_upgrade_call import RULE_DG_010, rule_dg010
from deployguard.rules.security.dg011_uups_delegatecall import RULE_DG_011, rule_dg011

# Register all security rules
registry.register_static(rule_dg005)
registry.register_static(rule_dg006)
registry.register_static(rule_dg007)
registry.register_static(rule_dg008)
registry.register_static(rule_dg009)
registry.register_static(rule_dg010)
registry.register_static(rule_dg011)

__all__ = [
    "RULE_DG_005",
    "RULE_DG_006",
    "RULE_DG_007",
    "RULE_DG_008",
    "RULE_DG_009",
    "RULE_DG_010",
    "RULE_DG_011",
    "rule_dg005",
    "rule_dg006",
    "rule_dg007",
    "rule_dg008",
    "rule_dg009",
    "rule_dg010",
    "rule_dg011",
]
