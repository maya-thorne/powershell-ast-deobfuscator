"""
PowerShell SecureString AST Reducer.
Statically analyzes and reduces ConvertTo-SecureString cmdlet invocations,
System.Runtime.InteropServices.Marshal BSTR unwrappers, and PSCredential / NetworkCredential
password extractions to clean, deobfuscated StringLiteralNode instances.
"""

from typing import Any, Dict, List, Optional, Tuple, Union

from .ast_nodes import (
    ASTNode,
    AssignmentNode,
    CommandNode,
    IdentifierNode,
    MemberAccessNode,
    MethodCallNode,
    ParenthesizedExpressionNode,
    PipelineNode,
    ScriptBlockNode,
    StaticMemberAccessNode,
    StringLiteralNode,
    SubexpressionNode,
    VariableNode,
)
from .secure_string_crypto import decrypt_secure_string
from .static_key_extractor import StaticKeyExtractor


class PowerShellSecureStringReducer:
    """
    Transforms obfuscated SecureString construction and unwrapping expressions
    into direct string literals through static decryption and symbol propagation.
    """

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols = symbols if symbols is not None else {}
        self.key_extractor = StaticKeyExtractor(symbols=self.symbols)

    def reduce(self, node: ASTNode) -> ASTNode:
        """Entry point for AST traversal and SecureString reduction."""
        return self.visit(node)

    def visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        if isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self.visit(s) for s in node.statements])
        if isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        if isinstance(node, CommandNode):
            return self.visit_command(node)
        if isinstance(node, AssignmentNode):
            return self.visit_assignment(node)
        if isinstance(node, StaticMemberAccessNode):
            return self.visit_static_member_access(node)
        if isinstance(node, MemberAccessNode):
            return self.visit_member_access(node)
        if isinstance(node, MethodCallNode):
            return self.visit_method_call(node)
        if isinstance(node, ParenthesizedExpressionNode):
            return self.visit_parenthesized(node)
        return node

    def visit_script_block(self, node: ScriptBlockNode) -> ScriptBlockNode:
        norm_stmts = [self.visit(s) for s in node.statements]
        return ScriptBlockNode(statements=norm_stmts)

    def visit_parenthesized(self, node: ParenthesizedExpressionNode) -> ASTNode:
        norm_inner = self.visit(node.expression)
        if isinstance(norm_inner, StringLiteralNode):
            return norm_inner
        return ParenthesizedExpressionNode(expression=norm_inner)

    def visit_assignment(self, node: AssignmentNode) -> AssignmentNode:
        norm_expr = self.visit(node.expression)
        var_name = node.variable.name.lower()

        # Track keys, strings, or credential payloads
        if isinstance(norm_expr, StringLiteralNode):
            self.symbols[var_name] = norm_expr.value
        else:
            key_bytes = self.key_extractor.extract_key(norm_expr)
            if key_bytes:
                self.symbols[var_name] = key_bytes

        return AssignmentNode(variable=node.variable, expression=norm_expr)

    def _parse_cmdlet_args(
        self, args: List[ASTNode]
    ) -> Tuple[Dict[str, Optional[ASTNode]], List[ASTNode]]:
        """Parses CommandNode argument list into named parameters and positional arguments."""
        named_args: Dict[str, Optional[ASTNode]] = {}
        positional_args: List[ASTNode] = []
        i = 0
        while i < len(args):
            arg = args[i]
            if isinstance(arg, IdentifierNode) and arg.name.startswith("-"):
                param_name = arg.name.lstrip("-").lower()
                if param_name in ("asplaintext", "force"):
                    named_args[param_name] = None
                    i += 1
                else:
                    if i + 1 < len(args) and not (
                        isinstance(args[i + 1], IdentifierNode)
                        and args[i + 1].name.startswith("-")
                    ):
                        named_args[param_name] = args[i + 1]
                        i += 2
                    else:
                        named_args[param_name] = None
                        i += 1
            else:
                positional_args.append(arg)
                i += 1
        return named_args, positional_args

    def _resolve_string(self, node: Optional[ASTNode]) -> Optional[str]:
        """Extracts constant string value from AST node or symbol table."""
        if node is None:
            return None
        if isinstance(node, StringLiteralNode):
            return node.value
        if isinstance(node, ParenthesizedExpressionNode):
            return self._resolve_string(node.expression)
        if isinstance(node, VariableNode):
            var_name = node.name.lower()
            val = self.symbols.get(var_name)
            if isinstance(val, str):
                return val
            if isinstance(val, ASTNode):
                return self._resolve_string(val)
        return None

    def _reduce_convert_to_secure_string(
        self,
        cmd: CommandNode,
        piped_input: Optional[ASTNode] = None,
    ) -> Optional[StringLiteralNode]:
        """Reduces ConvertTo-SecureString command to a decrypted StringLiteralNode."""
        target_name = ""
        if isinstance(cmd.target, IdentifierNode):
            target_name = cmd.target.name.lower()
        elif isinstance(cmd.target, StringLiteralNode):
            target_name = cmd.target.value.lower()

        if target_name != "convertto-securestring":
            return None

        named_args, positional_args = self._parse_cmdlet_args(cmd.arguments)

        # 1. Check -AsPlainText switch
        if "asplaintext" in named_args:
            plain_node = named_args.get("string")
            if plain_node is None and positional_args:
                plain_node = positional_args[0]
            if plain_node is None and piped_input is not None:
                plain_node = piped_input

            plain_str = self._resolve_string(plain_node)
            if plain_str is not None:
                return StringLiteralNode(value=plain_str)

        # 2. Check -Key / -SecureKey parameter
        key_node = named_args.get("key") or named_args.get("securekey")
        if key_node is None and len(positional_args) >= 2:
            key_node = positional_args[1]

        if key_node is not None:
            key_bytes = self.key_extractor.extract_key(key_node)
            if key_bytes is not None:
                enc_node = named_args.get("string")
                if enc_node is None and positional_args:
                    enc_node = positional_args[0]
                if enc_node is None and piped_input is not None:
                    enc_node = piped_input

                enc_str = self._resolve_string(enc_node)
                if enc_str is not None:
                    try:
                        decrypted = decrypt_secure_string(enc_str, key_bytes)
                        return StringLiteralNode(value=decrypted)
                    except Exception:
                        pass

        return None

    def visit_command(self, node: CommandNode) -> ASTNode:
        reduced = self._reduce_convert_to_secure_string(node)
        if reduced is not None:
            return reduced

        # Also reduce arguments
        norm_args = [self.visit(a) for a in node.arguments]
        return CommandNode(target=node.target, arguments=norm_args)

    def visit_pipeline(self, node: PipelineNode) -> ASTNode:
        norm_elements = [self.visit(e) for e in node.elements]

        # Check for piped ConvertTo-SecureString: <str> | ConvertTo-SecureString ...
        i = 0
        while i < len(norm_elements) - 1:
            left = norm_elements[i]
            right = norm_elements[i + 1]

            if isinstance(right, CommandNode):
                reduced = self._reduce_convert_to_secure_string(right, piped_input=left)
                if reduced is not None:
                    norm_elements[i : i + 2] = [reduced]
                    continue
            i += 1

        if len(norm_elements) == 1:
            return norm_elements[0]
        return PipelineNode(elements=norm_elements)

    def visit_static_member_access(self, node: StaticMemberAccessNode) -> ASTNode:
        type_lower = node.type_name.lower()
        member_lower = node.member.lower()

        # Handle Marshal unwrappers: [Marshal]::PtrToStringAuto([Marshal]::SecureStringToBSTR($sec))
        if type_lower.endswith("marshal"):
            if member_lower in (
                "ptrtostringauto",
                "ptrtostringbstr",
                "ptrtostringuni",
                "ptrtostringansi",
            ) and node.arguments:
                arg = node.arguments[0]
                inner_str = self._extract_inner_secure_payload(arg)
                if inner_str is not None:
                    return StringLiteralNode(value=inner_str)

            if member_lower in (
                "securestringtobstr",
                "securestringtoglobalallocansi",
                "securestringtoglobalallocunicode",
            ) and node.arguments:
                arg = node.arguments[0]
                inner_str = self._extract_inner_secure_payload(arg)
                if inner_str is not None:
                    return StringLiteralNode(value=inner_str)

        # Handle [System.Net.NetworkCredential]::new("", $sec)
        if type_lower.endswith("networkcredential") and member_lower in ("new", ".ctor"):
            # Arguments: [username, password]
            if node.arguments and len(node.arguments) >= 2:
                sec_arg = node.arguments[1]
                inner_str = self._extract_inner_secure_payload(sec_arg)
                if inner_str is not None:
                    # Stash credential mapping for subsequent property access
                    return StringLiteralNode(value=inner_str)

        return node

    def visit_member_access(self, node: MemberAccessNode) -> ASTNode:
        norm_target = self.visit(node.target)
        member_lower = node.member.lower()

        # Handle $cred.Password or (expr).Password
        if member_lower == "password":
            inner_str = self._extract_inner_secure_payload(norm_target)
            if inner_str is not None:
                return StringLiteralNode(value=inner_str)

        return MemberAccessNode(target=norm_target, member=node.member)

    def visit_method_call(self, node: MethodCallNode) -> ASTNode:
        norm_target = self.visit(node.target)
        method_lower = node.method_name.lower()

        # Handle $cred.GetNetworkCredential()
        if method_lower == "getnetworkcredential":
            inner_str = self._extract_inner_secure_payload(norm_target)
            if inner_str is not None:
                return StringLiteralNode(value=inner_str)

        norm_args = [self.visit(a) for a in node.arguments]
        return MethodCallNode(
            target=norm_target,
            method_name=node.method_name,
            arguments=norm_args,
        )

    def _extract_inner_secure_payload(self, node: Optional[ASTNode]) -> Optional[str]:
        """Recursively traces and extracts the plaintext string from a SecureString wrapper."""
        if node is None:
            return None

        if isinstance(node, StringLiteralNode):
            return node.value

        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_inner_secure_payload(node.expression)

        if isinstance(node, VariableNode):
            var_name = node.name.lower()
            val = self.symbols.get(var_name)
            if isinstance(val, str):
                return val
            if isinstance(val, ASTNode):
                return self._extract_inner_secure_payload(val)

        if isinstance(node, CommandNode):
            reduced = self._reduce_convert_to_secure_string(node)
            if reduced is not None:
                return reduced.value

            target_name = getattr(node.target, "name", "").lower()
            if target_name == "new-object":
                # Check New-Object PSCredential constructor call or args
                for arg in node.arguments:
                    if isinstance(arg, MethodCallNode) and "pscredential" in arg.method_name.lower():
                        if len(arg.arguments) >= 2:
                            return self._extract_inner_secure_payload(arg.arguments[1])
                    if isinstance(arg, ASTNode):
                        sub = self._extract_inner_secure_payload(arg)
                        if sub is not None:
                            return sub
                if len(node.arguments) >= 3:
                    type_str = getattr(node.arguments[0], "name", getattr(node.arguments[0], "value", "")).lower()
                    if "pscredential" in type_str:
                        return self._extract_inner_secure_payload(node.arguments[2])

            for arg in node.arguments:
                sub = self._extract_inner_secure_payload(arg)
                if sub is not None:
                    return sub

        if isinstance(node, MethodCallNode):
            if "pscredential" in node.method_name.lower() and len(node.arguments) >= 2:
                return self._extract_inner_secure_payload(node.arguments[1])
            sub = self._extract_inner_secure_payload(node.target)
            if sub is not None:
                return sub
            for arg in node.arguments:
                sub = self._extract_inner_secure_payload(arg)
                if sub is not None:
                    return sub

        if isinstance(node, StaticMemberAccessNode):
            if node.arguments:
                for arg in node.arguments:
                    sub = self._extract_inner_secure_payload(arg)
                    if sub is not None:
                        return sub

        if isinstance(node, MemberAccessNode):
            return self._extract_inner_secure_payload(node.target)

        return None

