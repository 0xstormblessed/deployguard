"""Tests for the Foundry script parser."""

from pathlib import Path

import pytest

from deployguard.models.static import (
    BoundaryType,
    DeploymentMethod,
    ProxyType,
    ScriptType,
)
from deployguard.static.parsers.foundry import FoundryScriptParser


class TestFoundryScriptParser:
    """Test suite for FoundryScriptParser."""

    @pytest.fixture
    def parser(self) -> FoundryScriptParser:
        """Create a parser instance."""
        return FoundryScriptParser()

    def test_parse_empty_source(self, parser: FoundryScriptParser) -> None:
        """Test parsing empty source code."""
        result = parser.parse_source("", "test.sol")
        assert result.file_path == "test.sol"
        assert result.script_type == ScriptType.FOUNDRY
        # Empty source should produce parse errors
        assert len(result.parse_errors) > 0 or len(result.parse_warnings) > 0

    def test_extract_pragma_version(self, parser: FoundryScriptParser) -> None:
        """Test pragma version extraction."""
        source = "pragma solidity ^0.8.19;"
        version = parser._extract_pragma_version(source)
        assert version == "^0.8.19"

    def test_extract_pragma_version_range(self, parser: FoundryScriptParser) -> None:
        """Test pragma version extraction with range."""
        source = "pragma solidity >=0.8.0 <0.9.0;"
        version = parser._extract_pragma_version(source)
        assert version == ">=0.8.0 <0.9.0"

    def test_extract_pragma_version_none(self, parser: FoundryScriptParser) -> None:
        """Test pragma version extraction with no pragma."""
        source = "contract Test {}"
        version = parser._extract_pragma_version(source)
        assert version is None

    def test_determine_solc_version_default(self, parser: FoundryScriptParser) -> None:
        """Test solc version determination with no pragma."""
        version = parser._determine_solc_version(None)
        assert version == "0.8.20"

    def test_determine_solc_version_0_8(self, parser: FoundryScriptParser) -> None:
        """Test solc version determination for 0.8.x."""
        version = parser._determine_solc_version("^0.8.19")
        assert version == "0.8.20"

    def test_determine_solc_version_0_7(self, parser: FoundryScriptParser) -> None:
        """Test solc version determination for 0.7.x."""
        version = parser._determine_solc_version("^0.7.0")
        assert version == "0.7.6"

    def test_is_empty_init_data_empty_string(self, parser: FoundryScriptParser) -> None:
        """Test empty init data detection with empty string."""
        assert parser._is_empty_init_data('""') is True
        assert parser._is_empty_init_data("''") is True
        assert parser._is_empty_init_data("") is True

    def test_is_empty_init_data_0x(self, parser: FoundryScriptParser) -> None:
        """Test empty init data detection with 0x."""
        assert parser._is_empty_init_data("0x") is True

    def test_is_empty_init_data_bytes_empty(self, parser: FoundryScriptParser) -> None:
        """Test empty init data detection with bytes("")."""
        assert parser._is_empty_init_data('bytes("")') is True
        assert parser._is_empty_init_data("bytes(0)") is True
        assert parser._is_empty_init_data("new bytes(0)") is True

    def test_is_empty_init_data_non_empty(self, parser: FoundryScriptParser) -> None:
        """Test empty init data detection with non-empty data."""
        assert parser._is_empty_init_data("abi.encodeCall(Token.init, ())") is False
        assert parser._is_empty_init_data("initData") is False

    def test_is_hardcoded_address(self, parser: FoundryScriptParser) -> None:
        """Test hardcoded address detection."""
        # Valid address literal
        node = {"nodeType": "Literal", "value": "0x1234567890123456789012345678901234567890"}
        assert parser._is_hardcoded_address(node) is True

        # Invalid - too short
        node = {"nodeType": "Literal", "value": "0x1234"}
        assert parser._is_hardcoded_address(node) is False

        # Not a literal
        node = {"nodeType": "Identifier", "name": "impl"}
        assert parser._is_hardcoded_address(node) is False

    def test_get_boundary_type(self, parser: FoundryScriptParser) -> None:
        """Test boundary type mapping."""
        assert parser._get_boundary_type("broadcast") == BoundaryType.VM_BROADCAST
        assert parser._get_boundary_type("startBroadcast") == BoundaryType.VM_START_BROADCAST
        assert parser._get_boundary_type("stopBroadcast") == BoundaryType.VM_STOP_BROADCAST

    def test_proxy_types_mapping(self, parser: FoundryScriptParser) -> None:
        """Test proxy types mapping is complete."""
        assert "ERC1967Proxy" in parser.PROXY_TYPES
        assert parser.PROXY_TYPES["ERC1967Proxy"] == ProxyType.ERC1967_PROXY

        assert "TransparentUpgradeableProxy" in parser.PROXY_TYPES
        assert (
            parser.PROXY_TYPES["TransparentUpgradeableProxy"]
            == ProxyType.TRANSPARENT_UPGRADEABLE_PROXY
        )

        assert "BeaconProxy" in parser.PROXY_TYPES
        assert parser.PROXY_TYPES["BeaconProxy"] == ProxyType.BEACON_PROXY

    def test_broadcast_functions(self, parser: FoundryScriptParser) -> None:
        """Test broadcast functions set is complete."""
        assert "broadcast" in parser.BROADCAST_FUNCTIONS
        assert "startBroadcast" in parser.BROADCAST_FUNCTIONS
        assert "stopBroadcast" in parser.BROADCAST_FUNCTIONS


class TestFoundryScriptParserIntegration:
    """Integration tests that require solc."""

    @pytest.fixture
    def parser(self) -> FoundryScriptParser:
        """Create a parser instance."""
        return FoundryScriptParser()

    @pytest.mark.slow
    def test_parse_simple_contract(self, parser: FoundryScriptParser) -> None:
        """Test parsing a simple contract (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SimpleContract {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }
}
"""
        result = parser.parse_source(source, "Simple.sol")
        assert result.file_path == "Simple.sol"
        assert result.script_type == ScriptType.FOUNDRY
        # No proxy deployments in this simple contract
        assert len(result.proxy_deployments) == 0

    @pytest.mark.slow
    def test_parse_vulnerable_deployment(self, parser: FoundryScriptParser) -> None:
        """Test parsing a vulnerable deployment script (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VulnerableScript {
    function run() external {
        MyToken impl = new MyToken();
        // VULNERABLE: empty init data
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), "");
        // Separate initialization call
        MyToken(address(proxy)).initialize("Token", "TKN");
    }
}

contract MyToken {
    function initialize(string memory, string memory) external {}
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}
"""
        result = parser.parse_source(source, "Vulnerable.s.sol")

        # Should detect the proxy deployment
        assert len(result.proxy_deployments) == 1
        deployment = result.proxy_deployments[0]
        assert deployment.proxy_type == ProxyType.ERC1967_PROXY
        assert deployment.has_empty_init is True
        assert deployment.is_atomic is False

    @pytest.mark.slow
    def test_parse_safe_deployment(self, parser: FoundryScriptParser) -> None:
        """Test parsing a safe deployment script (requires solc)."""
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
        result = parser.parse_source(source, "Safe.s.sol")

        # Should detect the proxy deployment
        assert len(result.proxy_deployments) == 1
        deployment = result.proxy_deployments[0]
        assert deployment.proxy_type == ProxyType.ERC1967_PROXY
        assert deployment.has_empty_init is False
        assert deployment.is_atomic is True

    @pytest.mark.slow
    def test_detect_broadcast_boundaries(self, parser: FoundryScriptParser) -> None:
        """Test detection of vm.broadcast boundaries (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface Vm {
    function startBroadcast() external;
    function stopBroadcast() external;
}

contract BroadcastScript {
    Vm internal vm;

    function run() external {
        vm.startBroadcast();
        // deployment code here
        vm.stopBroadcast();
    }
}
"""
        result = parser.parse_source(source, "Broadcast.s.sol")

        # Should detect broadcast boundaries
        assert len(result.tx_boundaries) >= 2

        boundary_types = [b.boundary_type for b in result.tx_boundaries]
        assert BoundaryType.VM_START_BROADCAST in boundary_types
        assert BoundaryType.VM_STOP_BROADCAST in boundary_types

    @pytest.mark.slow
    def test_detect_private_key_env(self, parser: FoundryScriptParser) -> None:
        """Test detection of vm.envUint("PRIVATE_KEY") (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface Vm {
    function envUint(string memory) external returns (uint256);
    function startBroadcast(uint256) external;
}

contract PrivateKeyScript {
    Vm internal vm;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);
    }
}
"""
        result = parser.parse_source(source, "PrivateKey.s.sol")
        assert result.has_private_key_env is True

    @pytest.mark.slow
    def test_detect_ownership_transfer(self, parser: FoundryScriptParser) -> None:
        """Test detection of transferOwnership calls (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface Ownable {
    function transferOwnership(address) external;
}

contract OwnershipScript {
    function run() external {
        Ownable token = Ownable(address(0));
        token.transferOwnership(address(0x123));
    }
}
"""
        result = parser.parse_source(source, "Ownership.s.sol")
        assert result.has_ownership_transfer is True

    @pytest.mark.slow
    def test_track_variable_assignments(self, parser: FoundryScriptParser) -> None:
        """Test variable assignment tracking (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VariableScript {
    function run() external {
        address impl = 0x1234567890123456789012345678901234567890;
        uint256 value = 100;
    }
}
"""
        result = parser.parse_source(source, "Variable.s.sol")

        # Should track variables
        assert "impl" in result.implementation_variables
        var_info = result.implementation_variables["impl"]
        assert var_info.is_hardcoded is True


class TestCreate2Detection:
    """Test CREATE2 and CreateX detection."""

    @pytest.fixture
    def parser(self) -> FoundryScriptParser:
        """Create a parser instance."""
        return FoundryScriptParser()

    def test_detect_proxy_in_bytecode(self, parser: FoundryScriptParser) -> None:
        """Test proxy detection in bytecode expressions."""
        # Should detect ERC1967Proxy
        bytecode = "abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, data))"
        assert parser._detect_proxy_in_bytecode(bytecode) == ProxyType.ERC1967_PROXY

        # Should detect TransparentUpgradeableProxy
        bytecode = "abi.encodePacked(type(TransparentUpgradeableProxy).creationCode, abi.encode(impl, admin, data))"
        assert parser._detect_proxy_in_bytecode(bytecode) == ProxyType.TRANSPARENT_UPGRADEABLE_PROXY

        # Should return None for non-proxy bytecode
        bytecode = "type(MyToken).creationCode"
        assert parser._detect_proxy_in_bytecode(bytecode) is None

    def test_extract_proxy_args_from_bytecode(self, parser: FoundryScriptParser) -> None:
        """Test extraction of impl and init data from bytecode expression."""
        # Standard abi.encode pattern
        bytecode = (
            "abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implAddress, initData))"
        )
        impl, init_data = parser._extract_proxy_args_from_bytecode(bytecode)
        assert impl == "implAddress"
        assert init_data == "initData"

        # Empty init data
        bytecode = 'abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, bytes("")))'
        impl, init_data = parser._extract_proxy_args_from_bytecode(bytecode)
        assert impl == "impl"
        assert init_data == 'bytes("")'

    @pytest.mark.slow
    def test_parse_createx_vulnerable_deployment(self, parser: FoundryScriptParser) -> None:
        """Test parsing a vulnerable CreateX deployment (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external returns (address);
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract VulnerableCreateX {
    ICreateX public createX;

    function deployProxy(address impl) external returns (address) {
        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, bytes(""))
        );
        return createX.deployCreate2(bytes32(0), bytecode);
    }
}
"""
        result = parser.parse_source(source, "VulnerableCreateX.s.sol")

        # Should detect the CreateX proxy deployment
        assert len(result.proxy_deployments) == 1
        deployment = result.proxy_deployments[0]
        assert deployment.proxy_type == ProxyType.ERC1967_PROXY
        assert deployment.deployment_method == DeploymentMethod.CREATEX
        assert deployment.has_empty_init is True

    @pytest.mark.slow
    def test_parse_createx_safe_deployment(self, parser: FoundryScriptParser) -> None:
        """Test parsing a safe CreateX deployment with init data (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external returns (address);
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract Token {
    function initialize(string memory name) external {}
}

contract SafeCreateX {
    ICreateX public createX;

    function deployProxy(address impl) external returns (address) {
        bytes memory initData = abi.encodeCall(Token.initialize, ("MyToken"));
        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, initData)
        );
        return createX.deployCreate2(bytes32(0), bytecode);
    }
}
"""
        result = parser.parse_source(source, "SafeCreateX.s.sol")

        # Should detect the CreateX proxy deployment
        assert len(result.proxy_deployments) == 1
        deployment = result.proxy_deployments[0]
        assert deployment.proxy_type == ProxyType.ERC1967_PROXY
        assert deployment.deployment_method == DeploymentMethod.CREATEX
        assert deployment.has_empty_init is False

    @pytest.mark.slow
    def test_parse_foundry_native_create2(self, parser: FoundryScriptParser) -> None:
        """Test parsing Foundry-native CREATE2 syntax (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract Token {
    function initialize(string memory name) external {}
}

contract NativeCreate2 {
    function deployProxy(address impl, bytes32 salt) external returns (address) {
        ERC1967Proxy proxy = new ERC1967Proxy{salt: salt}(
            impl,
            abi.encodeCall(Token.initialize, ("MyToken"))
        );
        return address(proxy);
    }
}
"""
        result = parser.parse_source(source, "NativeCreate2.s.sol")

        # Should detect the proxy deployment with CREATE2
        assert len(result.proxy_deployments) == 1
        deployment = result.proxy_deployments[0]
        assert deployment.proxy_type == ProxyType.ERC1967_PROXY
        assert deployment.deployment_method == DeploymentMethod.NEW_CREATE2
        assert deployment.salt is not None
        assert deployment.has_empty_init is False

    @pytest.mark.slow
    def test_parse_foundry_native_create2_vulnerable(self, parser: FoundryScriptParser) -> None:
        """Test parsing vulnerable Foundry-native CREATE2 with empty init (requires solc)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract VulnerableNativeCreate2 {
    function deployProxy(address impl, bytes32 salt) external returns (address) {
        // VULNERABLE: empty init data
        ERC1967Proxy proxy = new ERC1967Proxy{salt: salt}(impl, "");
        return address(proxy);
    }
}
"""
        result = parser.parse_source(source, "VulnerableNativeCreate2.s.sol")

        # Should detect the vulnerable proxy deployment
        assert len(result.proxy_deployments) == 1
        deployment = result.proxy_deployments[0]
        assert deployment.proxy_type == ProxyType.ERC1967_PROXY
        assert deployment.deployment_method == DeploymentMethod.NEW_CREATE2
        assert deployment.has_empty_init is True

    @pytest.mark.slow
    def test_parse_createx_and_init_safe(self, parser: FoundryScriptParser) -> None:
        """Test CreateX deployCreate2AndInit (safe pattern with separate init)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

struct Values {
    uint256 constructorAmount;
    uint256 initCallAmount;
}

interface ICreateX {
    function deployCreate2AndInit(bytes32 salt, bytes memory bytecode, bytes memory init, Values memory values) external returns (address);
}

contract SafeCreateX {
    ICreateX createX;

    function run() external {
        bytes32 salt = keccak256("salt");
        MyToken impl = new MyToken();

        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(impl), "")
        );

        // SAFE: Using deployCreate2AndInit with separate init data
        bytes memory initData = abi.encodeCall(MyToken.initialize, ("Token", "TKN"));
        Values memory vals = Values(0, 0);
        address proxy = createX.deployCreate2AndInit(salt, bytecode, initData, vals);
    }
}

contract MyToken {
    function initialize(string memory, string memory) external {}
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}
"""
        result = parser.parse_source(source, "SafeCreateX.s.sol")

        assert len(result.proxy_deployments) == 1
        deployment = result.proxy_deployments[0]
        assert deployment.proxy_type == ProxyType.ERC1967_PROXY
        assert deployment.deployment_method == DeploymentMethod.CREATEX
        # init_data_arg should be the separate init data, not the empty one in bytecode
        assert deployment.has_empty_init is False

    @pytest.mark.slow
    def test_parse_createx_clone_empty_init(self, parser: FoundryScriptParser) -> None:
        """Test CreateX deployCreate2Clone with empty init (vulnerable)."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ICreateX {
    function deployCreate2Clone(bytes32 salt, address impl, bytes memory init) external returns (address);
}

contract VulnerableClone {
    ICreateX createX;

    function run() external {
        bytes32 salt = keccak256("salt");
        address impl = address(0x1234567890123456789012345678901234567890);
        // VULNERABLE: Clone with empty init
        address proxy = createX.deployCreate2Clone(salt, impl, "");
    }
}
"""
        result = parser.parse_source(source, "VulnerableClone.s.sol")

        # Clone detection may not create a proxy deployment since it's not using bytecode pattern
        # This test verifies the parser handles clone syntax without errors
        assert len(result.parse_errors) == 0

    @pytest.mark.slow
    def test_parse_createx_single_arg(self, parser: FoundryScriptParser) -> None:
        """Test CreateX deployCreate2(bytes) single arg pattern."""
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface ICreateX {
    function deployCreate2(bytes memory bytecode) external returns (address);
}

contract SingleArgCreateX {
    ICreateX createX;

    function run() external {
        MyToken impl = new MyToken();

        // deployCreate2 with single arg (salt derived from msg.sender)
        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(impl), "")
        );

        address proxy = createX.deployCreate2(bytecode);
    }
}

contract MyToken {}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}
"""
        result = parser.parse_source(source, "SingleArgCreateX.s.sol")

        # Single-arg deployCreate2 may not be detected by current implementation
        # since it expects (salt, bytecode) pattern. This test ensures no errors.
        assert len(result.parse_errors) == 0

    @pytest.mark.slow
    def test_parse_createx_in_helper_function_with_assignment(
        self, parser: FoundryScriptParser
    ) -> None:
        """Test parsing CreateX in helper function with assignment (USPD pattern).

        This tests the specific pattern from USPD's deployUUPSProxy_NoInit where:
        1. The function returns a value via assignment to return variable
        2. The CreateX call is in an Assignment expression, not VariableDeclaration
        """
        source = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external payable returns (address);
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract DeployScript {
    ICreateX public createX;

    function deployUUPSProxy_NoInit(bytes32 salt, address implementationAddress) internal returns (address proxyAddress) {
        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(implementationAddress, bytes("")) // Empty init data for UUPS
        );
        proxyAddress = createX.deployCreate2{value: 0}(salt, bytecode);
    }
}
"""
        result = parser.parse_source(source, "DeployScript.s.sol")

        # Should detect the CreateX proxy deployment in helper function
        assert len(result.proxy_deployments) == 1
        deployment = result.proxy_deployments[0]
        assert deployment.proxy_type == ProxyType.ERC1967_PROXY
        assert deployment.deployment_method == DeploymentMethod.CREATEX
        assert deployment.has_empty_init is True
        # The bytecode variable should be resolved
        assert "ERC1967Proxy" in (deployment.bytecode_source or "")

    @pytest.mark.slow
    def test_parse_createx_inherited_helper_function(
        self, parser: FoundryScriptParser, tmp_path: Path
    ) -> None:
        """Test detection of vulnerable helper function in inherited contract.

        This mimics the real USPD bug where:
        1. DeployScript.sol defines deployUUPSProxy_NoInit with bytes("")
        2. 04-DeploySystemCore.s.sol inherits from DeployScript and calls the helper
        3. The vulnerability is in the INHERITED file, not the main script

        The parser must analyze ALL source files from compilation, not just the main file.
        """
        # Create the base contract with vulnerable helper
        base_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external payable returns (address);
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract DeployScript {
    ICreateX public createX;

    function deployUUPSProxy_NoInit(bytes32 salt, address impl) internal returns (address proxyAddress) {
        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, bytes(""))  // VULNERABLE: Empty init data
        );
        proxyAddress = createX.deployCreate2{value: 0}(salt, bytecode);
    }
}
"""

        # Create the main script that inherits and calls the helper
        main_script = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DeployScript.sol";

contract DeploySystemCore is DeployScript {
    function run() external {
        address impl = address(0x1234);
        bytes32 salt = bytes32(uint256(1));
        address proxy = deployUUPSProxy_NoInit(salt, impl);  // Calls vulnerable helper
    }
}
"""

        # Write files to tmp directory
        base_file = tmp_path / "DeployScript.sol"
        main_file = tmp_path / "DeploySystemCore.s.sol"
        base_file.write_text(base_contract)
        main_file.write_text(main_script)

        # Parse the main script - should detect vulnerability in inherited contract
        result = parser.parse_file(main_file)

        # The vulnerable pattern should be detected from the inherited DeployScript.sol
        assert len(result.proxy_deployments) >= 1, (
            f"Expected to find proxy deployment in inherited contract. "
            f"Parse errors: {result.parse_errors}"
        )

        # Find the vulnerable deployment
        vulnerable = [d for d in result.proxy_deployments if d.has_empty_init]
        assert len(vulnerable) >= 1, (
            f"Expected to find vulnerable (empty init) deployment. "
            f"Found deployments: {[(d.proxy_type, d.has_empty_init) for d in result.proxy_deployments]}"
        )


class TestProxyTypesAcrossInheritance:
    """Test detection of all proxy types across imports and inheritance."""

    @pytest.fixture
    def parser(self) -> FoundryScriptParser:
        """Create a parser instance."""
        return FoundryScriptParser()

    @pytest.mark.slow
    def test_transparent_proxy_in_inherited_contract(
        self, parser: FoundryScriptParser, tmp_path: Path
    ) -> None:
        """Test TransparentUpgradeableProxy detection in inherited helper."""
        base_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external payable returns (address);
}

contract TransparentUpgradeableProxy {
    constructor(address impl, address admin, bytes memory data) {}
}

contract BaseDeployer {
    ICreateX public createX;

    function deployTransparentProxy_NoInit(bytes32 salt, address impl, address admin) internal returns (address proxyAddress) {
        bytes memory bytecode = abi.encodePacked(
            type(TransparentUpgradeableProxy).creationCode,
            abi.encode(impl, admin, bytes(""))  // VULNERABLE: Empty init
        );
        proxyAddress = createX.deployCreate2{value: 0}(salt, bytecode);
    }
}
"""
        main_script = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseDeployer.sol";

contract MainScript is BaseDeployer {
    function run() external {
        deployTransparentProxy_NoInit(bytes32(0), address(0x1), address(0x2));
    }
}
"""
        base_file = tmp_path / "BaseDeployer.sol"
        main_file = tmp_path / "MainScript.s.sol"
        base_file.write_text(base_contract)
        main_file.write_text(main_script)

        result = parser.parse_file(main_file)

        assert len(result.proxy_deployments) >= 1
        vulnerable = [d for d in result.proxy_deployments if d.has_empty_init]
        assert len(vulnerable) >= 1
        assert vulnerable[0].proxy_type == ProxyType.TRANSPARENT_UPGRADEABLE_PROXY

    @pytest.mark.slow
    def test_beacon_proxy_in_inherited_contract(
        self, parser: FoundryScriptParser, tmp_path: Path
    ) -> None:
        """Test BeaconProxy detection in inherited helper."""
        base_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external payable returns (address);
}

contract BeaconProxy {
    constructor(address beacon, bytes memory data) {}
}

contract BaseDeployer {
    ICreateX public createX;

    function deployBeaconProxy_NoInit(bytes32 salt, address beacon) internal returns (address proxyAddress) {
        bytes memory bytecode = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(beacon, bytes(""))  // VULNERABLE: Empty init
        );
        proxyAddress = createX.deployCreate2{value: 0}(salt, bytecode);
    }
}
"""
        main_script = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseDeployer.sol";

contract MainScript is BaseDeployer {
    function run() external {
        deployBeaconProxy_NoInit(bytes32(0), address(0x1));
    }
}
"""
        base_file = tmp_path / "BaseDeployer.sol"
        main_file = tmp_path / "MainScript.s.sol"
        base_file.write_text(base_contract)
        main_file.write_text(main_script)

        result = parser.parse_file(main_file)

        assert len(result.proxy_deployments) >= 1
        vulnerable = [d for d in result.proxy_deployments if d.has_empty_init]
        assert len(vulnerable) >= 1
        assert vulnerable[0].proxy_type == ProxyType.BEACON_PROXY

    @pytest.mark.slow
    def test_erc1967_proxy_new_syntax_inherited(
        self, parser: FoundryScriptParser, tmp_path: Path
    ) -> None:
        """Test ERC1967Proxy with new syntax (not CreateX) in inherited contract."""
        base_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract BaseDeployer {
    function deployProxy_NoInit(address impl) internal returns (address) {
        // Using standard new syntax with CREATE2 salt
        ERC1967Proxy proxy = new ERC1967Proxy{salt: bytes32(uint256(1))}(impl, "");
        return address(proxy);
    }
}
"""
        main_script = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseDeployer.sol";

contract MainScript is BaseDeployer {
    function run() external {
        deployProxy_NoInit(address(0x1));
    }
}
"""
        base_file = tmp_path / "BaseDeployer.sol"
        main_file = tmp_path / "MainScript.s.sol"
        base_file.write_text(base_contract)
        main_file.write_text(main_script)

        result = parser.parse_file(main_file)

        assert len(result.proxy_deployments) >= 1
        vulnerable = [d for d in result.proxy_deployments if d.has_empty_init]
        assert len(vulnerable) >= 1
        assert vulnerable[0].proxy_type == ProxyType.ERC1967_PROXY
        assert vulnerable[0].deployment_method == DeploymentMethod.NEW_CREATE2

    @pytest.mark.slow
    def test_multiple_proxy_types_in_same_inherited_contract(
        self, parser: FoundryScriptParser, tmp_path: Path
    ) -> None:
        """Test detection of multiple proxy types in same inherited contract."""
        base_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external payable returns (address);
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract TransparentUpgradeableProxy {
    constructor(address impl, address admin, bytes memory data) {}
}

contract BaseDeployer {
    ICreateX public createX;

    function deployERC1967_NoInit(bytes32 salt, address impl) internal returns (address proxyAddress) {
        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, bytes(""))  // VULNERABLE
        );
        proxyAddress = createX.deployCreate2{value: 0}(salt, bytecode);
    }

    function deployTransparent_NoInit(bytes32 salt, address impl, address admin) internal returns (address proxyAddress) {
        bytes memory bytecode = abi.encodePacked(
            type(TransparentUpgradeableProxy).creationCode,
            abi.encode(impl, admin, bytes(""))  // VULNERABLE
        );
        proxyAddress = createX.deployCreate2{value: 0}(salt, bytecode);
    }
}
"""
        main_script = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseDeployer.sol";

contract MainScript is BaseDeployer {
    function run() external {
        deployERC1967_NoInit(bytes32(0), address(0x1));
        deployTransparent_NoInit(bytes32(0), address(0x2), address(0x3));
    }
}
"""
        base_file = tmp_path / "BaseDeployer.sol"
        main_file = tmp_path / "MainScript.s.sol"
        base_file.write_text(base_contract)
        main_file.write_text(main_script)

        result = parser.parse_file(main_file)

        # Should detect both proxy deployments
        assert len(result.proxy_deployments) >= 2
        vulnerable = [d for d in result.proxy_deployments if d.has_empty_init]
        assert len(vulnerable) >= 2

        proxy_types = {d.proxy_type for d in vulnerable}
        assert ProxyType.ERC1967_PROXY in proxy_types
        assert ProxyType.TRANSPARENT_UPGRADEABLE_PROXY in proxy_types

    @pytest.mark.slow
    def test_safe_proxy_in_inherited_contract(
        self, parser: FoundryScriptParser, tmp_path: Path
    ) -> None:
        """Test that safe (atomic init) proxies in inherited contracts are not flagged."""
        base_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external payable returns (address);
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

interface IToken {
    function initialize(string memory name) external;
}

contract BaseDeployer {
    ICreateX public createX;

    function deployProxy_WithInit(bytes32 salt, address impl) internal returns (address proxyAddress) {
        bytes memory initData = abi.encodeCall(IToken.initialize, ("MyToken"));
        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, initData)  // SAFE: Has init data
        );
        proxyAddress = createX.deployCreate2{value: 0}(salt, bytecode);
    }
}
"""
        main_script = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./BaseDeployer.sol";

contract MainScript is BaseDeployer {
    function run() external {
        deployProxy_WithInit(bytes32(0), address(0x1));
    }
}
"""
        base_file = tmp_path / "BaseDeployer.sol"
        main_file = tmp_path / "MainScript.s.sol"
        base_file.write_text(base_contract)
        main_file.write_text(main_script)

        result = parser.parse_file(main_file)

        # Should detect deployment but NOT as vulnerable
        assert len(result.proxy_deployments) >= 1
        vulnerable = [d for d in result.proxy_deployments if d.has_empty_init]
        assert len(vulnerable) == 0, "Safe proxy should not be flagged as vulnerable"

    @pytest.mark.slow
    def test_deep_inheritance_chain(self, parser: FoundryScriptParser, tmp_path: Path) -> None:
        """Test detection through deep inheritance chain (A -> B -> C)."""
        base_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external payable returns (address);
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract DeployHelpers {
    ICreateX public createX;

    function _deployProxy(bytes32 salt, address impl, bytes memory data) internal returns (address proxyAddress) {
        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, data)
        );
        proxyAddress = createX.deployCreate2{value: 0}(salt, bytecode);
    }
}
"""
        middle_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DeployHelpers.sol";

contract DeployBase is DeployHelpers {
    function deployUUPSProxy_NoInit(bytes32 salt, address impl) internal returns (address) {
        return _deployProxy(salt, impl, bytes(""));  // VULNERABLE: passes empty data
    }
}
"""
        main_script = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DeployBase.sol";

contract MainScript is DeployBase {
    function run() external {
        deployUUPSProxy_NoInit(bytes32(0), address(0x1));
    }
}
"""
        helpers_file = tmp_path / "DeployHelpers.sol"
        base_file = tmp_path / "DeployBase.sol"
        main_file = tmp_path / "MainScript.s.sol"
        helpers_file.write_text(base_contract)
        base_file.write_text(middle_contract)
        main_file.write_text(main_script)

        result = parser.parse_file(main_file)

        # Should detect deployment from base helper through middle contract
        assert len(result.proxy_deployments) >= 1
        # Note: The vulnerability detection depends on resolving the bytes("") literal
        # through the _deployProxy call, which may not detect empty init if passed as variable
        # This test verifies the inheritance chain is followed

    @pytest.mark.slow
    def test_location_shows_correct_file(self, parser: FoundryScriptParser, tmp_path: Path) -> None:
        """Test that vulnerability location shows correct file path, not main file."""
        base_contract = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory bytecode) external payable returns (address);
}

contract ERC1967Proxy {
    constructor(address impl, bytes memory data) {}
}

contract VulnerableBase {
    ICreateX public createX;

    function deployVulnerable(bytes32 salt, address impl) internal returns (address proxyAddress) {
        bytes memory bytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, bytes(""))
        );
        proxyAddress = createX.deployCreate2{value: 0}(salt, bytecode);
    }
}
"""
        main_script = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./VulnerableBase.sol";

contract MainScript is VulnerableBase {
    function run() external {
        deployVulnerable(bytes32(0), address(0x1));
    }
}
"""
        base_file = tmp_path / "VulnerableBase.sol"
        main_file = tmp_path / "MainScript.s.sol"
        base_file.write_text(base_contract)
        main_file.write_text(main_script)

        result = parser.parse_file(main_file)

        assert len(result.proxy_deployments) >= 1
        deployment = result.proxy_deployments[0]

        # Location should point to VulnerableBase.sol, not MainScript.s.sol
        assert (
            "VulnerableBase.sol" in deployment.location.file_path
        ), f"Expected location to be in VulnerableBase.sol, got: {deployment.location.file_path}"

        # Line content should show the actual vulnerable code
        assert deployment.location.line_content, "Expected line content to be populated"
        assert (
            "deployCreate2" in deployment.location.line_content
            or "createX" in deployment.location.line_content
        )
