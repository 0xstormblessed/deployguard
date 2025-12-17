"""Parser for Foundry/Forge deployment scripts using solc AST.

This parser uses the official Solidity compiler to generate an AST,
ensuring 100% accurate parsing for all Solidity versions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from solcx import compile_standard, get_installed_solc_versions, install_solc

from deployguard.models.core import SourceLocation
from deployguard.models.static import (
    BoundaryType,
    DeploymentMethod,
    FunctionCall,
    ProxyDeployment,
    ProxyType,
    ScriptAnalysis,
    ScriptType,
    TransactionBoundary,
    VariableInfo,
)
from deployguard.static.parsers.foundry_project import FoundryProject


class FoundryScriptParser:
    """Parser for Foundry/Forge deployment scripts using solc AST.

    This parser uses the official Solidity compiler to generate an AST,
    ensuring 100% accurate parsing for all Solidity versions.
    """

    # Known proxy contract types to detect
    PROXY_TYPES: dict[str, ProxyType] = {
        "ERC1967Proxy": ProxyType.ERC1967_PROXY,
        "TransparentUpgradeableProxy": ProxyType.TRANSPARENT_UPGRADEABLE_PROXY,
        "UUPSUpgradeable": ProxyType.UUPS_UPGRADEABLE,
        "BeaconProxy": ProxyType.BEACON_PROXY,
    }

    # vm.broadcast patterns (Foundry cheatcodes)
    BROADCAST_FUNCTIONS: set[str] = {
        "broadcast",
        "startBroadcast",
        "stopBroadcast",
    }

    # Known CREATE2 factory addresses (lowercase for comparison)
    CREATE2_FACTORY_ADDRESSES: set[str] = {
        "0x4e59b44847b379578588920ca78fbf26c0b4956c",  # Arachnid deterministic deployer
        "0xba5ed099633d3b313e4d5f7bdc1305d3c28ba5ed",  # CreateX
    }

    # Known CREATE2 factory variable name patterns (lowercase for comparison)
    CREATE2_FACTORY_NAMES: set[str] = {
        "createx",
        "create2deployer",
        "deployer",
        "factory",
        "create2factory",
        "deterministicdeployer",
    }

    def __init__(self) -> None:
        """Initialize the solc-based parser."""
        self.current_file: Path | None = None
        self.current_source_file: Path | None = (
            None  # Tracks current file being analyzed (for inherited contracts)
        )
        self.source_code: str = ""
        self.source_lines: list[str] = []

    def parse_file(self, file_path: Path) -> ScriptAnalysis:
        """Parse a Foundry deployment script.

        Args:
            file_path: Path to the .s.sol file

        Returns:
            ScriptAnalysis with detected patterns
        """
        self.current_file = file_path
        source = file_path.read_text(encoding="utf-8")
        return self.parse_source(source, str(file_path))

    def parse_source(self, source: str, file_path: str) -> ScriptAnalysis:
        """Parse Solidity source code using solc.

        Args:
            source: Solidity source code
            file_path: Path for error reporting

        Returns:
            ScriptAnalysis with detected patterns
        """
        self.source_code = source
        self.source_lines = source.split("\n")
        self.current_file = Path(file_path)

        analysis = ScriptAnalysis(
            file_path=file_path,
            script_type=ScriptType.FOUNDRY,
            proxy_deployments=[],
            tx_boundaries=[],
            implementation_variables={},
            parse_errors=[],
            parse_warnings=[],
        )

        try:
            # Detect Foundry project first (for remappings and solc version)
            remappings: list[str] = []
            project_root: Path | None = None
            foundry_solc_version: str | None = None

            if self.current_file:
                foundry_project = FoundryProject(self.current_file)
                if foundry_project.detect():
                    project_root = foundry_project.get_project_root()

                    # Check if lib directory has uninitialized dependencies
                    lib_ok, empty_libs = foundry_project.check_lib_initialized()
                    if not lib_ok:
                        empty_list = ", ".join(empty_libs[:5])
                        if len(empty_libs) > 5:
                            empty_list += f", ... and {len(empty_libs) - 5} more"
                        analysis.parse_errors.append(
                            f"Foundry dependencies not installed. Empty lib directories: {empty_list}. "
                            "Run 'forge install' or 'git submodule update --init --recursive' to install dependencies."
                        )
                        return analysis

                    remappings = foundry_project.get_remappings_list()
                    foundry_solc_version = foundry_project.get_solc_version()

                    if remappings:
                        analysis.parse_warnings.append(
                            f"Detected Foundry project with {len(remappings)} remappings"
                        )

                    # Validate dependencies exist
                    missing_deps = foundry_project.validate_dependencies()
                    if missing_deps:
                        for dep in missing_deps[:3]:  # Show first 3
                            analysis.parse_warnings.append(f"Missing dependency: {dep}")
                        if len(missing_deps) > 3:
                            analysis.parse_warnings.append(
                                f"...and {len(missing_deps) - 3} more missing dependencies"
                            )
                        analysis.parse_warnings.append(
                            "Run 'forge install' to install missing dependencies"
                        )

            # Determine solc version: prefer foundry.toml, fall back to pragma
            if foundry_solc_version:
                solc_version = foundry_solc_version
                analysis.parse_warnings.append(f"Using solc {solc_version} from foundry.toml")
            else:
                pragma_version = self._extract_pragma_version(source)
                solc_version = self._determine_solc_version(pragma_version)

            installed = get_installed_solc_versions()
            installed_strs = [str(v) for v in installed]
            if solc_version not in installed_strs:
                # Check if we can use an installed compatible version
                compatible = None
                for inst_ver in sorted(installed_strs, reverse=True):
                    if inst_ver.startswith(solc_version.rsplit(".", 1)[0]):
                        # Same major.minor version
                        compatible = inst_ver
                        break

                if compatible:
                    analysis.parse_warnings.append(
                        f"solc {solc_version} not installed, using compatible {compatible}"
                    )
                    solc_version = compatible
                else:
                    analysis.parse_warnings.append(f"Installing solc {solc_version}...")
                    install_solc(solc_version)

            # Compile to get AST
            input_json: dict[str, Any] = {
                "language": "Solidity",
                "sources": {file_path: {"content": source}},
                "settings": {
                    "outputSelection": {"*": {"": ["ast"]}},
                },
            }

            # Add remappings if detected
            if remappings:
                input_json["settings"]["remappings"] = remappings

            # Build allow_paths for solc to access imports
            allow_paths: list[str] = []
            if project_root:
                allow_paths.append(str(project_root))
            if self.current_file:
                allow_paths.append(str(self.current_file.parent))

            output = compile_standard(
                input_json,
                solc_version=solc_version,
                allow_paths=allow_paths if allow_paths else None,
            )

            # Check for errors
            if "errors" in output:
                for error in output["errors"]:
                    if error.get("severity") == "error":
                        analysis.parse_errors.append(error.get("formattedMessage", ""))
                    else:
                        analysis.parse_warnings.append(error.get("formattedMessage", ""))

            # Build source code map for all compiled files
            # This is needed to extract source snippets from inherited contracts
            source_code_map: dict[str, str] = {}
            if "sources" in output:
                for source_path, source_info in output["sources"].items():
                    # solc output includes absolute paths, we need to read the source
                    try:
                        source_file = Path(source_path)
                        if source_file.exists():
                            source_code_map[source_path] = source_file.read_text()
                    except Exception:
                        pass

            # Extract AST from all sources (includes inherited contracts)
            # This is critical for detecting vulnerabilities in inherited helper functions
            if "sources" in output:
                for source_path, source_info in output["sources"].items():
                    if "ast" in source_info:
                        ast = source_info["ast"]
                        # Switch source context for proper source snippet extraction
                        # Use absolutePath from AST if available, otherwise use the key
                        actual_path = ast.get("absolutePath", source_path)
                        if source_path in source_code_map:
                            self.source_code = source_code_map[source_path]
                            self.source_lines = self.source_code.split("\n")
                            # Track current source file for accurate location reporting
                            self.current_source_file = Path(actual_path)
                        self._analyze_ast(ast, analysis)

                # Restore original source context
                self.source_code = source
                self.source_lines = source.split("\n")
                self.current_source_file = self.current_file

            # Post-process to calculate transaction scope boundaries
            self._calculate_scope_boundaries(analysis)

        except Exception as e:
            analysis.parse_errors.append(f"Parse error: {e}")

        return analysis

    def _analyze_ast(self, ast: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Analyze AST to extract deployment patterns.

        Args:
            ast: solc AST (SourceUnit node)
            analysis: Analysis result to populate
        """
        if ast.get("nodeType") != "SourceUnit":
            return

        # Find all contract definitions (deployment scripts)
        for node in ast.get("nodes", []):
            if node.get("nodeType") == "ContractDefinition":
                self._analyze_contract(node, analysis)

    def _analyze_contract(self, contract: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Analyze a contract for deployment patterns.

        Args:
            contract: ContractDefinition AST node
            analysis: Analysis result to populate
        """
        for node in contract.get("nodes", []):
            if node.get("nodeType") == "FunctionDefinition":
                self._analyze_function(node, analysis)

    def _analyze_function(self, func: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Analyze a function for deployment patterns.

        Looks for:
        - vm.broadcast() calls (transaction boundaries)
        - new ProxyContract() calls (proxy deployments)
        - Variable assignments

        Args:
            func: FunctionDefinition AST node
            analysis: Analysis result to populate
        """
        body = func.get("body")
        if not body:
            return

        # Traverse all statements in function body
        self._traverse_statements(body.get("statements", []), analysis)

    def _traverse_statements(
        self, statements: list[dict[str, Any]], analysis: ScriptAnalysis
    ) -> None:
        """Recursively traverse statements looking for patterns."""
        for stmt in statements:
            node_type = stmt.get("nodeType")

            # Check for vm.broadcast() calls
            if node_type == "ExpressionStatement":
                expr = stmt.get("expression", {})
                self._check_broadcast_call(expr, analysis)
                self._check_proxy_deployment(expr, analysis)
                self._check_createx_deployment(expr, analysis)
                self._check_private_key_env(expr, analysis)
                self._check_ownership_transfer(expr, analysis)
                self._check_function_call(expr, analysis)
                self._check_validation_pattern(expr, analysis)

                # Also check Assignment expressions (e.g., proxyAddress = createX.deployCreate2(...))
                if expr.get("nodeType") == "Assignment":
                    rhs = expr.get("rightHandSide", {})
                    self._check_proxy_deployment(rhs, analysis)
                    self._check_createx_deployment(rhs, analysis)

            # Check variable declarations with proxy deployments
            elif node_type == "VariableDeclarationStatement":
                init_value = stmt.get("initialValue", {})

                # Track proxy deployments assigned to variables
                num_deployments_before = len(analysis.proxy_deployments)
                self._check_proxy_deployment(init_value, analysis)
                self._check_createx_deployment(init_value, analysis)

                # If a proxy was just deployed, capture the variable name
                if len(analysis.proxy_deployments) > num_deployments_before:
                    # Get variable name from declaration
                    declarations = stmt.get("declarations", [])
                    if declarations and declarations[0]:
                        var_name = declarations[0].get("name", "")
                        if var_name:
                            # Update the last deployment with variable name
                            analysis.proxy_deployments[-1].proxy_variable = var_name

                self._check_private_key_env(init_value, analysis)
                self._track_variable_assignment(stmt, analysis)

            # Recurse into blocks
            elif node_type == "Block":
                self._traverse_statements(stmt.get("statements", []), analysis)

            # Recurse into if statements
            elif node_type == "IfStatement":
                true_body = stmt.get("trueBody", {})
                if true_body.get("nodeType") == "Block":
                    self._traverse_statements(true_body.get("statements", []), analysis)
                false_body = stmt.get("falseBody")
                if false_body:
                    if false_body.get("nodeType") == "Block":
                        self._traverse_statements(false_body.get("statements", []), analysis)

            # Recurse into for loops
            elif node_type == "ForStatement":
                loop_body = stmt.get("body", {})
                if loop_body.get("nodeType") == "Block":
                    self._traverse_statements(loop_body.get("statements", []), analysis)

            # Recurse into while loops
            elif node_type == "WhileStatement":
                loop_body = stmt.get("body", {})
                if loop_body.get("nodeType") == "Block":
                    self._traverse_statements(loop_body.get("statements", []), analysis)

            # Check return statements for proxy deployments
            elif node_type == "Return":
                expr = stmt.get("expression", {})
                if expr:
                    self._check_proxy_deployment(expr, analysis)
                    self._check_createx_deployment(expr, analysis)

    def _check_broadcast_call(self, expr: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Check if expression is a vm.broadcast() call.

        Args:
            expr: Expression AST node
            analysis: Analysis to update
        """
        if expr.get("nodeType") != "FunctionCall":
            return

        callee = expr.get("expression", {})

        # Check for vm.broadcast(), vm.startBroadcast(), vm.stopBroadcast()
        if callee.get("nodeType") == "MemberAccess":
            member_name = callee.get("memberName", "")
            base_expr = callee.get("expression", {})

            # Check if base is "vm"
            if (
                base_expr.get("nodeType") == "Identifier"
                and base_expr.get("name") == "vm"
                and member_name in self.BROADCAST_FUNCTIONS
            ):
                location = self._extract_location(expr)
                boundary = TransactionBoundary(
                    boundary_type=self._get_boundary_type(member_name),
                    location=location,
                    scope_start=location.line_number,
                )
                analysis.tx_boundaries.append(boundary)

    def _check_proxy_deployment(self, expr: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Check if expression is a proxy contract deployment.

        Detects both:
        - new ProxyContract(impl, data)
        - new ProxyContract{salt: salt}(impl, data)  # Foundry-native CREATE2

        Args:
            expr: Expression AST node
            analysis: Analysis to update
        """
        if expr.get("nodeType") != "FunctionCall":
            return

        callee = expr.get("expression", {})
        salt = None

        # Handle FunctionCallOptions wrapper for new Contract{salt: ...}() syntax
        # AST structure: FunctionCall -> FunctionCallOptions -> NewExpression
        if callee.get("nodeType") == "FunctionCallOptions":
            # Extract salt from options
            salt = self._extract_create2_salt_from_options(callee)
            # Unwrap to get the NewExpression
            callee = callee.get("expression", {})

        # Check for "new ProxyContract(...)" pattern
        if callee.get("nodeType") == "NewExpression":
            type_name = callee.get("typeName", {})

            # Get contract name being instantiated
            contract_name = None
            if type_name.get("nodeType") == "UserDefinedTypeName":
                # Handle both pathNode and name patterns
                path_node = type_name.get("pathNode", {})
                if path_node:
                    contract_name = path_node.get("name", "")
                else:
                    # Fallback to direct name
                    contract_name = type_name.get("name", "")

            if contract_name and contract_name in self.PROXY_TYPES:
                deployment = self._parse_proxy_deployment(
                    expr, contract_name, self.PROXY_TYPES[contract_name], salt=salt
                )
                analysis.proxy_deployments.append(deployment)

    def _check_private_key_env(self, expr: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Check for vm.envUint("PRIVATE_KEY") pattern.

        Args:
            expr: Expression AST node
            analysis: Analysis to update
        """
        if expr.get("nodeType") != "FunctionCall":
            return

        callee = expr.get("expression", {})

        if callee.get("nodeType") == "MemberAccess":
            member_name = callee.get("memberName", "")
            base_expr = callee.get("expression", {})

            if (
                base_expr.get("nodeType") == "Identifier"
                and base_expr.get("name") == "vm"
                and member_name in ("envUint", "envBytes32", "envString")
            ):
                # Check if argument contains "PRIVATE_KEY"
                args = expr.get("arguments", [])
                if args:
                    arg_source = self._extract_argument_source(args[0])
                    if "PRIVATE_KEY" in arg_source.upper():
                        analysis.has_private_key_env = True

    def _check_ownership_transfer(self, expr: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Check for transferOwnership() calls.

        Args:
            expr: Expression AST node
            analysis: Analysis to update
        """
        if expr.get("nodeType") != "FunctionCall":
            return

        callee = expr.get("expression", {})

        if callee.get("nodeType") == "MemberAccess":
            member_name = callee.get("memberName", "")
            if member_name == "transferOwnership":
                analysis.has_ownership_transfer = True

    def _check_function_call(self, expr: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Detect function calls like proxy.initialize().

        Args:
            expr: Expression AST node
            analysis: Analysis to update
        """
        if expr.get("nodeType") != "FunctionCall":
            return

        callee = expr.get("expression", {})

        # Look for member access pattern: variable.functionName()
        if callee.get("nodeType") == "MemberAccess":
            member_name = callee.get("memberName", "")
            base_expr = callee.get("expression", {})

            # Get the receiver variable name
            if base_expr.get("nodeType") == "Identifier":
                receiver = base_expr.get("name", "")
                if receiver and member_name:
                    location = self._extract_location(expr)
                    function_call = FunctionCall(
                        receiver=receiver,
                        function_name=member_name,
                        location=location,
                    )
                    analysis.function_calls.append(function_call)

    def _check_validation_pattern(self, expr: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Detect validation patterns like require(impl.code.length > 0).

        Args:
            expr: Expression AST node
            analysis: Analysis to update
        """
        if expr.get("nodeType") != "FunctionCall":
            return

        callee = expr.get("expression", {})

        # Look for require() calls
        if callee.get("nodeType") == "Identifier" and callee.get("name") == "require":
            # Extract source code to analyze
            arg_source = ""
            args = expr.get("arguments", [])
            if args:
                arg_source = self._extract_argument_source(args[0])

            # Check for validation patterns
            validated_vars = self._extract_validated_variables(arg_source)
            for var_name in validated_vars:
                # Mark variable as validated
                if var_name in analysis.implementation_variables:
                    analysis.implementation_variables[var_name].is_validated = True

    def _extract_validated_variables(self, condition: str) -> set[str]:
        """Extract variable names from validation conditions.

        Looks for patterns like:
        - impl.code.length > 0
        - impl != address(0)
        - isContract(impl)

        Args:
            condition: Source code of require() condition

        Returns:
            Set of variable names being validated
        """
        validated_vars: set[str] = set()

        # Pattern 1: variable.code.length > 0
        matches = re.findall(r"(\w+)\.code\.length\s*>\s*0", condition)
        validated_vars.update(matches)

        # Pattern 2: variable != address(0)
        matches = re.findall(r"(\w+)\s*!=\s*address\(0\)", condition)
        validated_vars.update(matches)

        # Pattern 3: isContract(variable)
        matches = re.findall(r"isContract\((\w+)\)", condition)
        validated_vars.update(matches)

        # Pattern 4: variable != 0 or variable != address(0x0)
        matches = re.findall(r"(\w+)\s*!=\s*(?:0|address\(0x0+\))", condition)
        validated_vars.update(matches)

        return validated_vars

    def _extract_create2_salt_from_options(self, options_node: dict[str, Any]) -> str | None:
        """Extract salt from FunctionCallOptions node.

        In Solidity 0.8+, CREATE2 can be used via:
            new Contract{salt: mySalt}(args...)

        The AST represents this as:
            FunctionCall
              expression: FunctionCallOptions
                expression: NewExpression
                names: ["salt"]
                options: [<salt value node>]

        Args:
            options_node: FunctionCallOptions AST node

        Returns:
            Salt value as string if found, None otherwise
        """
        # FunctionCallOptions has 'names' and 'options' arrays
        names = options_node.get("names", [])
        options = options_node.get("options", [])

        if "salt" in names:
            idx = names.index("salt")
            if idx < len(options):
                return self._extract_argument_source(options[idx])

        return None

    def _check_createx_deployment(self, expr: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Check for CreateX deployCreate2() or similar CREATE2 factory patterns.

        Detects:
        - createX.deployCreate2(salt, bytecode)
        - createX.deployCreate2{value: X}(salt, bytecode)
        - ICreateX(0xba5Ed...).deployCreate2(salt, bytecode)
        - Similar patterns from other CREATE2 factories

        Args:
            expr: Expression AST node
            analysis: Analysis to update
        """
        if expr.get("nodeType") != "FunctionCall":
            return

        callee = expr.get("expression", {})
        # Handle FunctionCallOptions wrapper (for {value: X} syntax)
        if callee.get("nodeType") == "FunctionCallOptions":
            callee = callee.get("expression", {})

        # Check for member access pattern: createX.deployCreate2(...)
        if callee.get("nodeType") == "MemberAccess":
            member_name = callee.get("memberName", "")
            base_expr = callee.get("expression", {})

            # Check for createX.deployCreate2 or similar patterns
            if member_name in (
                "deployCreate2",
                "deployCreate",
                "deploy",
                "safeCreate2",
                "deployCreate2AndInit",
            ):
                is_create2_factory = self._is_create2_factory(base_expr)

                if is_create2_factory:
                    deployment = self._parse_createx_deployment(expr, member_name, analysis)
                    if deployment:
                        analysis.proxy_deployments.append(deployment)

    def _is_create2_factory(self, expr: dict[str, Any]) -> bool:
        """Check if expression refers to a CREATE2 factory.

        Checks for:
        - Variable names like createX, deployer, factory (case-insensitive)
        - Known factory addresses (0x4e59b44847b379578588920ca78fbf26c0b4956c, etc.)
        - Type casts to factory interfaces: ICreateX(address)

        Args:
            expr: AST expression node

        Returns:
            True if this appears to be a CREATE2 factory
        """
        node_type = expr.get("nodeType", "")

        # Check identifier names (case-insensitive)
        if node_type == "Identifier":
            name = expr.get("name", "").lower()
            return name in self.CREATE2_FACTORY_NAMES

        # Check member access (e.g., this.createX)
        if node_type == "MemberAccess":
            member_name = expr.get("memberName", "").lower()
            return member_name in self.CREATE2_FACTORY_NAMES

        # Check function calls - type casts like ICreateX(0xba5Ed...)
        if node_type == "FunctionCall":
            callee = expr.get("expression", {})

            # Check for interface cast pattern: ICreateX(address)
            if callee.get("nodeType") == "Identifier":
                cast_name = callee.get("name", "").lower()
                # Common CREATE2 factory interface names
                if any(
                    factory in cast_name
                    for factory in ("createx", "create2", "deployer", "factory")
                ):
                    return True

            # Check if the argument is a known factory address
            args = expr.get("arguments", [])
            if args:
                arg_source = self._extract_argument_source(args[0])
                if arg_source.lower() in self.CREATE2_FACTORY_ADDRESSES:
                    return True

        # Check for literal addresses
        if node_type == "Literal":
            value = expr.get("value", "").lower()
            return value in self.CREATE2_FACTORY_ADDRESSES

        return False

    def _parse_createx_deployment(
        self, expr: dict[str, Any], method_name: str, analysis: ScriptAnalysis | None = None
    ) -> ProxyDeployment | None:
        """Parse a CreateX deployCreate2() call to extract proxy deployment info.

        CreateX patterns:
            createX.deployCreate2(salt, bytecode)
            createX.deployCreate2AndInit(salt, bytecode, init, values)

        Where bytecode is often:
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData))

        Or bytecode might be a variable:
            bytes memory bytecode = abi.encodePacked(...);
            createX.deployCreate2(salt, bytecode);

        For deployCreate2AndInit, even if bytecode has empty init data, the separate
        init parameter provides initialization, making it safe (atomic).

        Args:
            expr: FunctionCall AST node
            method_name: Name of the deploy method
            analysis: Optional ScriptAnalysis to resolve variable references

        Returns:
            ProxyDeployment if proxy bytecode detected, None otherwise
        """
        args = expr.get("arguments", [])
        if len(args) < 2:
            return None

        # First arg is salt, second is bytecode
        salt = self._extract_argument_source(args[0])
        bytecode_arg = self._extract_argument_source(args[1])

        # If bytecode_arg is a simple identifier, try to resolve it from tracked variables
        if analysis and bytecode_arg and re.match(r"^\w+$", bytecode_arg.strip()):
            var_name = bytecode_arg.strip()
            if var_name in analysis.implementation_variables:
                var_info = analysis.implementation_variables[var_name]
                if var_info.assigned_value:
                    bytecode_arg = var_info.assigned_value

        # Check if bytecode contains proxy creation code
        proxy_type = self._detect_proxy_in_bytecode(bytecode_arg)
        if not proxy_type:
            return None

        # Extract implementation and init data from bytecode expression
        impl_arg, init_data_arg = self._extract_proxy_args_from_bytecode(bytecode_arg, proxy_type)

        has_empty_init = self._is_empty_init_data(init_data_arg)

        # For deployCreate2AndInit, check the 3rd argument (init parameter)
        # Even if bytecode has empty init, the separate init param makes it safe
        if method_name == "deployCreate2AndInit" and len(args) >= 3:
            separate_init = self._extract_argument_source(args[2])
            # Resolve variable if needed
            if analysis and separate_init and re.match(r"^\w+$", separate_init.strip()):
                var_name = separate_init.strip()
                if var_name in analysis.implementation_variables:
                    var_info = analysis.implementation_variables[var_name]
                    if var_info.assigned_value:
                        separate_init = var_info.assigned_value
            # If separate init has actual data, it's safe (atomic)
            if separate_init and not self._is_empty_init_data(separate_init):
                has_empty_init = False
                init_data_arg = separate_init

        return ProxyDeployment(
            proxy_type=proxy_type,
            implementation_arg=impl_arg,
            init_data_arg=init_data_arg,
            location=self._extract_location(expr),
            has_empty_init=has_empty_init,
            is_atomic=not has_empty_init,
            deployment_method=DeploymentMethod.CREATEX,
            salt=salt,
            bytecode_source=bytecode_arg,
        )

    def _detect_proxy_in_bytecode(self, bytecode_expr: str) -> ProxyType | None:
        """Detect if bytecode expression contains proxy creation code.

        Looks for patterns like:
        - type(ERC1967Proxy).creationCode
        - type(TransparentUpgradeableProxy).creationCode

        Args:
            bytecode_expr: Source code of bytecode expression

        Returns:
            ProxyType if detected, None otherwise
        """
        for contract_name, proxy_type in self.PROXY_TYPES.items():
            if f"type({contract_name}).creationCode" in bytecode_expr:
                return proxy_type
        return None

    def _extract_proxy_args_from_bytecode(
        self, bytecode_expr: str, proxy_type: ProxyType | None = None
    ) -> tuple[str, str]:
        """Extract implementation and init data from bytecode expression.

        Parses patterns like:
            abi.encodePacked(
                type(ERC1967Proxy).creationCode,
                abi.encode(impl, initData)
            )

        For TransparentUpgradeableProxy (3 args: impl, admin, data):
            abi.encode(impl, admin, data)

        Args:
            bytecode_expr: Source code of bytecode expression
            proxy_type: Type of proxy to help determine argument positions

        Returns:
            Tuple of (implementation_arg, init_data_arg)
        """
        impl_arg = ""
        init_data_arg = ""

        # Extract all arguments from abi.encode(...) using balanced paren matching
        # Find the start of abi.encode(
        encode_start = bytecode_expr.find("abi.encode(")
        if encode_start != -1:
            # Find matching closing paren
            start_idx = encode_start + len("abi.encode(")
            args_str = self._extract_balanced_parens(bytecode_expr[start_idx:])
            # Split by comma but handle nested parens like bytes("")
            args = self._split_args(args_str) if args_str else []
        else:
            args = []

        if len(args) >= 2:
            impl_arg = args[0].strip()
            # For TransparentUpgradeableProxy: args are (impl, admin, data)
            # For ERC1967Proxy/BeaconProxy: args are (impl, data)
            if proxy_type == ProxyType.TRANSPARENT_UPGRADEABLE_PROXY and len(args) >= 3:
                init_data_arg = args[2].strip()
            else:
                init_data_arg = args[-1].strip()  # Last arg is always init data

            # Remove trailing comments that may have been captured
            if "//" in init_data_arg:
                init_data_arg = init_data_arg.split("//")[0].strip()
        else:
            # Try abi.encodeCall pattern
            encode_call_match = re.search(r"abi\.encodeCall\s*\(.+\)", bytecode_expr, re.DOTALL)
            if encode_call_match:
                # Has init call - not empty
                init_data_arg = encode_call_match.group(0)

        return impl_arg, init_data_arg

    def _split_args(self, args_str: str) -> list[str]:
        """Split arguments by comma, handling nested parentheses.

        Args:
            args_str: Comma-separated arguments string

        Returns:
            List of individual arguments
        """
        args = []
        current_arg = ""
        paren_depth = 0

        for char in args_str:
            if char == "(":
                paren_depth += 1
                current_arg += char
            elif char == ")":
                paren_depth -= 1
                current_arg += char
            elif char == "," and paren_depth == 0:
                args.append(current_arg.strip())
                current_arg = ""
            else:
                current_arg += char

        if current_arg.strip():
            args.append(current_arg.strip())

        return args

    def _extract_balanced_parens(self, s: str) -> str:
        """Extract content within balanced parentheses.

        Given a string starting after an opening paren, extract everything
        up to the matching closing paren.

        Args:
            s: String starting after the opening paren

        Returns:
            Content between balanced parens (excluding the final closing paren)
        """
        result = ""
        paren_depth = 1  # We're already inside the first paren

        for char in s:
            if char == "(":
                paren_depth += 1
                result += char
            elif char == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    # Found matching closing paren
                    return result
                result += char
            else:
                result += char

        # No matching closing paren found
        return result

    def _parse_proxy_deployment(
        self,
        expr: dict[str, Any],
        contract_name: str,
        proxy_type: ProxyType,
        salt: str | None = None,
    ) -> ProxyDeployment:
        """Parse a proxy deployment expression.

        Args:
            expr: FunctionCall AST node for "new ProxyContract(...)"
            contract_name: Name of proxy contract
            proxy_type: Type of proxy
            salt: CREATE2 salt if using new Contract{salt: ...}() syntax

        Returns:
            ProxyDeployment with extracted info
        """
        args = expr.get("arguments", [])

        # Extract implementation argument (first arg for most proxies)
        impl_arg = self._extract_argument_source(args[0]) if args else ""

        # Extract init data argument (second arg for ERC1967, third for Transparent)
        init_data_arg = ""
        if proxy_type == ProxyType.TRANSPARENT_UPGRADEABLE_PROXY and len(args) >= 3:
            init_data_arg = self._extract_argument_source(args[2])
        elif len(args) >= 2:
            init_data_arg = self._extract_argument_source(args[1])

        # Check if init data is empty
        has_empty_init = self._is_empty_init_data(init_data_arg)

        # Determine deployment method based on salt presence
        deployment_method = DeploymentMethod.NEW_CREATE2 if salt else DeploymentMethod.NEW

        return ProxyDeployment(
            proxy_type=proxy_type,
            implementation_arg=impl_arg,
            init_data_arg=init_data_arg,
            location=self._extract_location(expr),
            has_empty_init=has_empty_init,
            is_atomic=not has_empty_init,  # Will be refined by tx boundary analysis
            deployment_method=deployment_method,
            salt=salt,
        )

    def _is_empty_init_data(self, init_data: str) -> bool:
        """Check if initialization data is empty.

        Args:
            init_data: Source code of init data argument

        Returns:
            True if init data is empty ("", "0x", bytes(""))
        """
        cleaned = init_data.strip().strip('"').strip("'")

        # Empty patterns - exact matches
        empty_patterns = {
            "",
            "0x",
            '""',
            "''",
            "bytes(0)",
            'bytes("")',
            "new bytes(0)",
        }

        if cleaned in empty_patterns or cleaned == "":
            return True

        # Regex patterns for more flexible matching
        empty_regexes = [
            r'^bytes\s*\(\s*["\']?\s*["\']?\s*\)?$',  # bytes(""), bytes(''), bytes("")
            r"^new\s+bytes\s*\(\s*0\s*\)$",  # new bytes(0)
            r'^["\']["\']$',  # "" or ''
            r"^0x$",  # 0x
        ]

        for pattern in empty_regexes:
            if re.match(pattern, cleaned):
                return True

        return False

    def _extract_argument_source(self, arg: dict[str, Any]) -> str:
        """Extract source code for an argument expression.

        Args:
            arg: AST node for argument

        Returns:
            Source code string
        """
        if "src" in arg:
            src = arg["src"]
            parts = src.split(":")
            if len(parts) >= 2:
                start = int(parts[0])
                length = int(parts[1])
                return self.source_code[start : start + length]
        return ""

    def _extract_location(self, node: dict[str, Any]) -> SourceLocation:
        """Extract source location from AST node.

        Args:
            node: AST node with 'src' field

        Returns:
            SourceLocation with line/column info
        """
        # Use current_source_file for inherited contracts, fallback to current_file
        source_file = self.current_source_file or self.current_file

        if "src" not in node:
            return SourceLocation(
                file_path=str(source_file) if source_file else "",
                line_number=0,
            )

        src = node["src"]
        parts = src.split(":")
        start = int(parts[0])

        # Calculate line number
        line_number = self.source_code[:start].count("\n") + 1

        # Get line content (strip leading/trailing whitespace for display)
        line_content = ""
        if line_number <= len(self.source_lines):
            line_content = self.source_lines[line_number - 1].strip()

        return SourceLocation(
            file_path=str(source_file) if source_file else "",
            line_number=line_number,
            line_content=line_content,
        )

    def _extract_pragma_version(self, source: str) -> str | None:
        """Extract pragma solidity version from source."""
        match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        return match.group(1).strip() if match else None

    def _determine_solc_version(self, pragma_version: str | None) -> str:
        """Determine which solc version to use based on pragma.

        Args:
            pragma_version: Pragma version string (e.g., "^0.8.30", ">=0.7.0 <0.9.0", "0.8.29")

        Returns:
            Specific solc version to use (e.g., "0.8.29")
        """
        try:
            from solcx import get_installable_solc_versions
        except ImportError:
            return "0.8.20"

        if not pragma_version:
            return self._get_latest_version_in_range("0.8.0", "0.9.0") or "0.8.20"

        pragma_version = pragma_version.strip()

        # Handle caret (^) - ^X.Y.Z means >=X.Y.Z <(X+1).0.0
        if pragma_version.startswith("^"):
            version_str = pragma_version[1:]
            version_match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version_str)
            if version_match:
                major, minor, patch = map(int, version_match.groups())
                # Try exact version first
                if self._is_version_available(version_str):
                    return version_str
                # Otherwise find latest in range
                min_version = f"{major}.{minor}.{patch}"
                max_version = f"{major + 1}.0.0"
                resolved = self._get_latest_version_in_range(min_version, max_version)
                if resolved:
                    return resolved
                return self._legacy_version_fallback(version_str)

        # Handle exact version (e.g., "0.8.29")
        if re.match(r"^\d+\.\d+\.\d+$", pragma_version):
            if self._is_version_available(pragma_version):
                return pragma_version
            # Try to find compatible version
            parts = pragma_version.split(".")
            return self._get_latest_version_in_range(
                pragma_version,
                f"{parts[0]}.{int(parts[1]) + 1}.0",
            ) or self._legacy_version_fallback(pragma_version)

        # Handle >= or > ranges
        if ">=" in pragma_version or ">" in pragma_version:
            min_match = re.search(r">=?(\d+\.\d+\.\d+)", pragma_version)
            max_match = re.search(r"<(\d+\.\d+\.\d+)", pragma_version)
            if min_match:
                min_ver = min_match.group(1)
                max_ver = (
                    max_match.group(1) if max_match else f"{int(min_ver.split('.')[0]) + 1}.0.0"
                )
                resolved = self._get_latest_version_in_range(min_ver, max_ver)
                if resolved:
                    return resolved

        return self._get_latest_version_in_range("0.8.0", "0.9.0") or "0.8.20"

    def _is_version_available(self, version: str) -> bool:
        """Check if a specific solc version is available for installation."""
        try:
            from solcx import get_installable_solc_versions

            available = get_installable_solc_versions()
            return any(str(v) == version for v in available)
        except Exception:
            return False

    def _get_latest_version_in_range(self, min_version: str, max_version: str) -> str | None:
        """Get the latest available solc version within a range."""
        try:
            from packaging import version as pkg_version
            from solcx import get_installable_solc_versions

            available = get_installable_solc_versions()
            matching = []
            min_ver = pkg_version.parse(min_version)
            max_ver = pkg_version.parse(max_version)

            for v in available:
                v_str = str(v)
                v_parsed = pkg_version.parse(v_str)
                if min_ver <= v_parsed < max_ver:
                    matching.append(v_str)

            if matching:
                matching.sort(key=lambda x: pkg_version.parse(x), reverse=True)
                return matching[0]
        except Exception:
            pass
        return None

    def _legacy_version_fallback(self, version_str: str) -> str:
        """Fallback for legacy version handling when exact version unavailable."""
        if version_str.startswith("0.8"):
            return "0.8.20"
        elif version_str.startswith("0.7"):
            return "0.7.6"
        elif version_str.startswith("0.6"):
            return "0.6.12"
        elif version_str.startswith("0.5"):
            return "0.5.17"
        elif version_str.startswith("0.4"):
            return "0.4.26"
        return "0.8.20"

    def _get_boundary_type(self, func_name: str) -> BoundaryType:
        """Map function name to boundary type."""
        mapping = {
            "broadcast": BoundaryType.VM_BROADCAST,
            "startBroadcast": BoundaryType.VM_START_BROADCAST,
            "stopBroadcast": BoundaryType.VM_STOP_BROADCAST,
        }
        return mapping.get(func_name, BoundaryType.VM_BROADCAST)

    def _track_variable_assignment(self, stmt: dict[str, Any], analysis: ScriptAnalysis) -> None:
        """Track variable assignments for data flow analysis."""
        # Extract variable declarations
        declarations = stmt.get("declarations", [])
        init_value = stmt.get("initialValue", {})

        for decl in declarations:
            if decl and decl.get("name"):
                var_name = decl["name"]
                var_info = VariableInfo(
                    name=var_name,
                    assigned_value=(
                        self._extract_argument_source(init_value) if init_value else None
                    ),
                    assignment_location=self._extract_location(stmt),
                    is_hardcoded=self._is_hardcoded_address(init_value),
                    is_validated=False,  # Will be updated by validation pattern detection
                )
                analysis.implementation_variables[var_name] = var_info

    def _is_hardcoded_address(self, expr: dict[str, Any]) -> bool:
        """Check if expression is a hardcoded address literal."""
        if expr.get("nodeType") == "Literal":
            value = expr.get("value", "")
            # Check for address literal (0x + 40 hex chars)
            return bool(re.match(r"^0x[a-fA-F0-9]{40}$", value))
        return False

    def _calculate_scope_boundaries(self, analysis: ScriptAnalysis) -> None:
        """Calculate scope_end for transaction boundaries by pairing start/stop.

        This pairs up vm.startBroadcast() with vm.stopBroadcast() to determine
        the line range for each broadcast scope.

        Args:
            analysis: Analysis to update with scope_end values
        """
        boundaries = analysis.tx_boundaries

        # Stack to track nested startBroadcast calls
        start_stack: list[int] = []

        for i, boundary in enumerate(boundaries):
            if boundary.boundary_type == BoundaryType.VM_START_BROADCAST:
                # Push start boundary index onto stack
                start_stack.append(i)
            elif boundary.boundary_type == BoundaryType.VM_STOP_BROADCAST:
                # Pop matching start and set its scope_end
                if start_stack:
                    start_idx = start_stack.pop()
                    boundaries[start_idx].scope_end = boundary.location.line_number
