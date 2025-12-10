"""Tests for the static analyzer."""

import pytest

from deployguard.models.rules import Severity
from deployguard.static.analyzer import (
    RULE_DG_001,
    RULE_DG_002,
    RULE_DG_003,
    RULE_DG_004,
    StaticAnalyzer,
)


class TestStaticAnalyzer:
    """Test suite for StaticAnalyzer."""

    @pytest.fixture
    def analyzer(self) -> StaticAnalyzer:
        """Create an analyzer instance."""
        return StaticAnalyzer()

    def test_analyzer_init(self, analyzer: StaticAnalyzer) -> None:
        """Test analyzer initialization."""
        assert analyzer.parser is not None
        assert analyzer.config is None

    def test_rules_defined(self) -> None:
        """Test that all rules are properly defined."""
        assert RULE_DG_001.rule_id == "DG-001"
        assert RULE_DG_001.severity == Severity.CRITICAL

        assert RULE_DG_002.rule_id == "DG-002"
        assert RULE_DG_002.severity == Severity.HIGH

        assert RULE_DG_003.rule_id == "DG-003"
        assert RULE_DG_003.severity == Severity.MEDIUM

        assert RULE_DG_004.rule_id == "DG-004"
        assert RULE_DG_004.severity == Severity.LOW


class TestStaticAnalyzerIntegration:
    """Integration tests that require solc."""

    @pytest.fixture
    def analyzer(self) -> StaticAnalyzer:
        """Create an analyzer instance."""
        return StaticAnalyzer()

    @pytest.mark.slow
    def test_analyze_vulnerable_script(self, analyzer: StaticAnalyzer) -> None:
        """Test analyzing a vulnerable deployment script."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VulnerableScript {
    function run() external {
        MyToken impl = new MyToken();
        // VULNERABLE: empty init data
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), "");
    }
}

contract MyToken {}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}
"""
        analysis = analyzer.analyze_source(source, "Vulnerable.s.sol")
        violations = analyzer.run_rules(analysis)

        # Should find DG-001 (non-atomic init)
        dg001_violations = [v for v in violations if v.rule.rule_id == "DG-001"]
        assert len(dg001_violations) == 1
        assert dg001_violations[0].severity == Severity.CRITICAL

    @pytest.mark.slow
    def test_analyze_safe_script(self, analyzer: StaticAnalyzer) -> None:
        """Test analyzing a safe deployment script."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SafeScript {
    function run() external {
        MyToken impl = new MyToken();
        // SAFE: atomic initialization
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(MyToken.initialize, ("Token", "TKN"))
        );
    }
}

contract MyToken {
    function initialize(string memory, string memory) external {}
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}
"""
        analysis = analyzer.analyze_source(source, "Safe.s.sol")
        violations = analyzer.run_rules(analysis)

        # Should not find DG-001 (safe atomic init)
        dg001_violations = [v for v in violations if v.rule.rule_id == "DG-001"]
        assert len(dg001_violations) == 0

    @pytest.mark.slow
    def test_analyze_hardcoded_address(self, analyzer: StaticAnalyzer) -> None:
        """Test detecting hardcoded implementation address."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract HardcodedScript {
    function run() external {
        // VULNERABLE: hardcoded implementation address
        ERC1967Proxy proxy = new ERC1967Proxy(
            0x1234567890123456789012345678901234567890,
            abi.encodeCall(MyToken.initialize, ())
        );
    }
}

contract MyToken {
    function initialize() external {}
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}
"""
        analysis = analyzer.analyze_source(source, "Hardcoded.s.sol")
        violations = analyzer.run_rules(analysis)

        # Should find DG-003 (hardcoded address)
        dg003_violations = [v for v in violations if v.rule.rule_id == "DG-003"]
        assert len(dg003_violations) == 1
        assert dg003_violations[0].severity == Severity.MEDIUM

    @pytest.mark.slow
    def test_analyze_transparent_proxy(self, analyzer: StaticAnalyzer) -> None:
        """Test analyzing TransparentUpgradeableProxy deployment."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract TransparentScript {
    function run() external {
        MyToken impl = new MyToken();
        address admin = address(this);
        // VULNERABLE: empty init data (third arg)
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            admin,
            ""
        );
    }
}

contract MyToken {}

contract TransparentUpgradeableProxy {
    constructor(address impl, address admin, bytes memory data) {}
}
"""
        analysis = analyzer.analyze_source(source, "Transparent.s.sol")
        violations = analyzer.run_rules(analysis)

        # Should find DG-001 for empty init
        dg001_violations = [v for v in violations if v.rule.rule_id == "DG-001"]
        assert len(dg001_violations) == 1

    @pytest.mark.slow
    def test_violations_have_recommendations(self, analyzer: StaticAnalyzer) -> None:
        """Test that all violations have recommendations."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ViolationsScript {
    function run() external {
        // Multiple issues
        ERC1967Proxy proxy = new ERC1967Proxy(
            0x1234567890123456789012345678901234567890,
            ""
        );
    }
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}
"""
        analysis = analyzer.analyze_source(source, "Violations.s.sol")
        violations = analyzer.run_rules(analysis)

        # All violations must have recommendations
        for violation in violations:
            assert violation.recommendation, f"{violation.rule.rule_id} missing recommendation"
            assert len(violation.recommendation) > 10, f"{violation.rule.rule_id} recommendation too short"
