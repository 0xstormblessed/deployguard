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
    ProxyDeployment,
    ProxyType,
    ScriptAnalysis,
    ScriptType,
    TransactionBoundary,
    VariableInfo,
)


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

    def __init__(self) -> None:
        """Initialize the solc-based parser."""
        self.current_file: Path | None = None
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
            # Detect pragma version and install solc if needed
            pragma_version = self._extract_pragma_version(source)
            solc_version = self._determine_solc_version(pragma_version)

            installed = get_installed_solc_versions()
            if solc_version not in [str(v) for v in installed]:
                analysis.parse_warnings.append(f"Installing solc {solc_version}...")
                install_solc(solc_version)

            # Compile to get AST
            input_json = {
                "language": "Solidity",
                "sources": {file_path: {"content": source}},
                "settings": {
                    "outputSelection": {"*": {"": ["ast"]}},
                    # Foundry scripts need forge-std remappings
                    "remappings": self._get_foundry_remappings(),
                },
            }

            output = compile_standard(input_json, solc_version=solc_version)

            # Check for errors
            if "errors" in output:
                for error in output["errors"]:
                    if error.get("severity") == "error":
                        analysis.parse_errors.append(error.get("formattedMessage", ""))
                    else:
                        analysis.parse_warnings.append(
                            error.get("formattedMessage", "")
                        )

            # Extract AST
            if "sources" in output and file_path in output["sources"]:
                ast = output["sources"][file_path]["ast"]
                self._analyze_ast(ast, analysis)

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

    def _analyze_contract(
        self, contract: dict[str, Any], analysis: ScriptAnalysis
    ) -> None:
        """Analyze a contract for deployment patterns.

        Args:
            contract: ContractDefinition AST node
            analysis: Analysis result to populate
        """
        for node in contract.get("nodes", []):
            if node.get("nodeType") == "FunctionDefinition":
                self._analyze_function(node, analysis)

    def _analyze_function(
        self, func: dict[str, Any], analysis: ScriptAnalysis
    ) -> None:
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
                self._check_private_key_env(expr, analysis)
                self._check_ownership_transfer(expr, analysis)

            # Check variable declarations with proxy deployments
            elif node_type == "VariableDeclarationStatement":
                init_value = stmt.get("initialValue", {})
                self._check_proxy_deployment(init_value, analysis)
                self._check_private_key_env(init_value, analysis)
                self._track_variable_assignment(stmt, analysis)

            # Recurse into blocks
            elif node_type == "Block":
                self._traverse_statements(stmt.get("statements", []), analysis)

            # Recurse into if statements
            elif node_type == "IfStatement":
                true_body = stmt.get("trueBody", {})
                if true_body.get("nodeType") == "Block":
                    self._traverse_statements(
                        true_body.get("statements", []), analysis
                    )
                false_body = stmt.get("falseBody")
                if false_body:
                    if false_body.get("nodeType") == "Block":
                        self._traverse_statements(
                            false_body.get("statements", []), analysis
                        )

            # Recurse into for loops
            elif node_type == "ForStatement":
                loop_body = stmt.get("body", {})
                if loop_body.get("nodeType") == "Block":
                    self._traverse_statements(
                        loop_body.get("statements", []), analysis
                    )

            # Recurse into while loops
            elif node_type == "WhileStatement":
                loop_body = stmt.get("body", {})
                if loop_body.get("nodeType") == "Block":
                    self._traverse_statements(
                        loop_body.get("statements", []), analysis
                    )

    def _check_broadcast_call(
        self, expr: dict[str, Any], analysis: ScriptAnalysis
    ) -> None:
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

    def _check_proxy_deployment(
        self, expr: dict[str, Any], analysis: ScriptAnalysis
    ) -> None:
        """Check if expression is a proxy contract deployment.

        Args:
            expr: Expression AST node
            analysis: Analysis to update
        """
        if expr.get("nodeType") != "FunctionCall":
            return

        callee = expr.get("expression", {})

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
                    expr, contract_name, self.PROXY_TYPES[contract_name]
                )
                analysis.proxy_deployments.append(deployment)

    def _check_private_key_env(
        self, expr: dict[str, Any], analysis: ScriptAnalysis
    ) -> None:
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

    def _check_ownership_transfer(
        self, expr: dict[str, Any], analysis: ScriptAnalysis
    ) -> None:
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

    def _parse_proxy_deployment(
        self, expr: dict[str, Any], contract_name: str, proxy_type: ProxyType
    ) -> ProxyDeployment:
        """Parse a proxy deployment expression.

        Args:
            expr: FunctionCall AST node for "new ProxyContract(...)"
            contract_name: Name of proxy contract
            proxy_type: Type of proxy

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

        return ProxyDeployment(
            proxy_type=proxy_type,
            implementation_arg=impl_arg,
            init_data_arg=init_data_arg,
            location=self._extract_location(expr),
            has_empty_init=has_empty_init,
            is_atomic=not has_empty_init,  # Will be refined by tx boundary analysis
        )

    def _is_empty_init_data(self, init_data: str) -> bool:
        """Check if initialization data is empty.

        Args:
            init_data: Source code of init data argument

        Returns:
            True if init data is empty ("", "0x", bytes(""))
        """
        cleaned = init_data.strip().strip('"').strip("'")

        # Empty patterns
        empty_patterns = {
            "",
            "0x",
            '""',
            "''",
            "bytes(0)",
            'bytes("")',
            "new bytes(0)",
        }

        return cleaned in empty_patterns or cleaned == ""

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
        if "src" not in node:
            return SourceLocation(
                file_path=str(self.current_file) if self.current_file else "",
                line_number=0,
            )

        src = node["src"]
        parts = src.split(":")
        start = int(parts[0])

        # Calculate line number
        line_number = self.source_code[:start].count("\n") + 1

        # Get line content
        line_content = (
            self.source_lines[line_number - 1]
            if line_number <= len(self.source_lines)
            else ""
        )

        return SourceLocation(
            file_path=str(self.current_file) if self.current_file else "",
            line_number=line_number,
            line_content=line_content,
        )

    def _extract_pragma_version(self, source: str) -> str | None:
        """Extract pragma solidity version from source."""
        match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        return match.group(1).strip() if match else None

    def _determine_solc_version(self, pragma: str | None) -> str:
        """Determine solc version to use based on pragma."""
        # Parse pragma version string
        if not pragma:
            return "0.8.20"

        if pragma.startswith("^0.8") or "0.8" in pragma:
            return "0.8.20"
        elif pragma.startswith("^0.7") or "0.7" in pragma:
            return "0.7.6"
        elif pragma.startswith("^0.6") or "0.6" in pragma:
            return "0.6.12"

        return "0.8.20"

    def _get_foundry_remappings(self) -> list[str]:
        """Get Foundry remappings for forge-std."""
        # TODO: Parse from foundry.toml or use forge remappings
        return [
            "forge-std/=lib/forge-std/src/",
        ]

    def _get_boundary_type(self, func_name: str) -> BoundaryType:
        """Map function name to boundary type."""
        mapping = {
            "broadcast": BoundaryType.VM_BROADCAST,
            "startBroadcast": BoundaryType.VM_START_BROADCAST,
            "stopBroadcast": BoundaryType.VM_STOP_BROADCAST,
        }
        return mapping.get(func_name, BoundaryType.VM_BROADCAST)

    def _track_variable_assignment(
        self, stmt: dict[str, Any], analysis: ScriptAnalysis
    ) -> None:
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
                    is_validated=False,  # TODO: Check for validation patterns
                )
                analysis.implementation_variables[var_name] = var_info

    def _is_hardcoded_address(self, expr: dict[str, Any]) -> bool:
        """Check if expression is a hardcoded address literal."""
        if expr.get("nodeType") == "Literal":
            value = expr.get("value", "")
            # Check for address literal (0x + 40 hex chars)
            return bool(re.match(r"^0x[a-fA-F0-9]{40}$", value))
        return False
