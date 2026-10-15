"""
PowerShell AST IEX (Invoke-Expression) Wrapper Tracking & Peeling Engine.
Recursively traces, extracts, and strips multi-nested dynamic execution layers
(iex, Invoke-Expression, call operators, ScriptBlock.Create, ExecutionContext, and pipelines)
to unmask the underlying payload AST.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .ast_nodes import (
    ASTNode,
    ArrayLiteralNode,
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
    DynamicMemberAccessNode,
    DynamicMethodCallNode,
    DynamicStaticMemberAccessNode,
    ForEachStatementNode,
    ForStatementNode,
    FormatOpNode,
    IdentifierNode,
    IfStatementNode,
    IndexAccessNode,
    MemberAccessNode,
    MethodCallNode,
    NumberLiteralNode,
    ParenthesizedExpressionNode,
    PipelineNode,
    RangeExpressionNode,
    ScriptBlockNode,
    StaticMemberAccessNode,
    StringLiteralNode,
    SubexpressionNode,
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)
from .lexer import PowerShellLexer
from .parser import PowerShellParser


@dataclass
class IEXLayer:
    """Forensic record of a peeled or detected IEX execution wrapper layer."""
    layer_index: int
    vector: str  # 'cmdlet', 'call_operator', 'scriptblock_create', 'execution_context', 'pipeline'
    invoker: str  # e.g., 'iex', 'Invoke-Expression', '&', '[scriptblock]::Create'
    raw_payload: str
    parsed_ast_type: str
    is_terminal: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer_index": self.layer_index,
            "vector": self.vector,
            "invoker": self.invoker,
            "raw_payload": self.raw_payload,
            "parsed_ast_type": self.parsed_ast_type,
            "is_terminal": self.is_terminal,
        }


@dataclass
class IEXUnwrapResult:
    """Composite result of IEX unwrapping and forensic telemetry."""
    unwrapped_ast: ASTNode
    layers: List[IEXLayer] = field(default_factory=list)
    total_depth: int = 0
    is_peeled: bool = False
    vectors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_depth": self.total_depth,
            "is_peeled": self.is_peeled,
            "vectors": self.vectors,
            "layers": [layer.to_dict() for layer in self.layers],
        }


class PowerShellIEXUnwrapper:
    """
    Compiler-grade IEX wrapper tracking and peeling engine.
    Detects and unwraps:
      - Direct cmdlets: `iex $code`, `Invoke-Expression $code`, `iex ($code)`
      - Nested wrappers: `iex (iex (iex $code))`
      - Call/dot operators: `& 'iex' $code`, `. 'Invoke-Expression' $code`, `& iex $code`
      - ScriptBlock methods: `[scriptblock]::Create($code).Invoke()`, `.InvokeReturnAsIs()`
      - ExecutionContext methods: `$ExecutionContext.InvokeCommand.InvokeScript($code)`
      - Pipeline stages: `$code | iex`, `$code | Invoke-Expression`, `$code | iex | iex`
      - Alias & variable invocations: tracking resolved symbol names
    """

    MAX_DEPTH: int = 30
    IEX_NAMES: Set[str] = {"iex", "invoke-expression"}
    SCRIPTBLOCK_TYPES: Set[str] = {
        "scriptblock",
        "system.management.automation.scriptblock",
    }
    SCRIPTBLOCK_METHODS: Set[str] = {
        "invoke",
        "invokereturnasis",
        "invokewithcontext",
    }

    def __init__(
        self,
        symbols: Optional[Dict[str, Any]] = None,
        max_depth: int = 30,
        unwrap_iex: bool = True,
    ):
        self.symbols = symbols if symbols is not None else {}
        self.max_depth = min(max_depth, self.MAX_DEPTH)
        self.unwrap_iex = unwrap_iex
        self.last_layers: List[IEXLayer] = []
        self.seen_hashes: Set[str] = set()

    def unwrap(self, node: ASTNode) -> ASTNode:
        """Entry point: unwraps all IEX wrappers across the entire AST."""
        if not self.unwrap_iex:
            return node
        self.last_layers = []
        self.seen_hashes.clear()
        return self.visit(node)

    def unwrap_with_telemetry(self, node: ASTNode) -> IEXUnwrapResult:
        """Unwraps all IEX wrappers and returns structured forensic telemetry."""
        unwrapped = self.unwrap(node)
        vectors = sorted(list({layer.vector for layer in self.last_layers}))
        return IEXUnwrapResult(
            unwrapped_ast=unwrapped,
            layers=list(self.last_layers),
            total_depth=len(self.last_layers),
            is_peeled=len(self.last_layers) > 0,
            vectors=vectors,
        )

    def visit(self, node: Optional[ASTNode]) -> Optional[ASTNode]:
        """Recursive AST visitor traversing nodes and peeling IEX wrappers."""
        if node is None:
            return None

        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, CommandNode):
            return self.visit_command(node)
        elif isinstance(node, MethodCallNode):
            return self.visit_method_call(node)
        elif isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self.visit(s) for s in node.statements])
        elif isinstance(node, ParenthesizedExpressionNode):
            return ParenthesizedExpressionNode(expression=self.visit(node.expression))
        elif isinstance(node, IfStatementNode):
            return IfStatementNode(
                condition=self.visit(node.condition),
                then_branch=self.visit(node.then_branch),
                else_branch=self.visit(node.else_branch) if node.else_branch else None,
            )
        elif isinstance(node, WhileStatementNode):
            return WhileStatementNode(condition=self.visit(node.condition), body=self.visit(node.body))
        elif isinstance(node, ForStatementNode):
            return ForStatementNode(
                initializer=self.visit(node.initializer) if node.initializer else None,
                condition=self.visit(node.condition) if node.condition else None,
                iterator=self.visit(node.iterator) if node.iterator else None,
                body=self.visit(node.body) if node.body else None,
            )
        elif isinstance(node, ForEachStatementNode):
            return ForEachStatementNode(
                variable=self.visit(node.variable) if node.variable else None,
                collection=self.visit(node.collection) if node.collection else None,
                body=self.visit(node.body) if node.body else None,
            )
        elif isinstance(node, AssignmentNode):
            return AssignmentNode(variable=self.visit(node.variable), expression=self.visit(node.expression))
        elif isinstance(node, BinaryOpNode):
            return BinaryOpNode(left=self.visit(node.left), operator=node.operator, right=self.visit(node.right))
        elif isinstance(node, UnaryOpNode):
            return UnaryOpNode(operator=node.operator, operand=self.visit(node.operand))
        elif isinstance(node, FormatOpNode):
            return FormatOpNode(
                format_string=self.visit(node.format_string),
                arguments=[self.visit(a) for a in node.arguments],
            )
        elif isinstance(node, TypeCastNode):
            return TypeCastNode(type_name=node.type_name, expression=self.visit(node.expression))
        elif isinstance(node, MemberAccessNode):
            return MemberAccessNode(target=self.visit(node.target), member=node.member)
        elif isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self.visit(node.target), index=self.visit(node.index))
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        return node

    def visit_script_block(self, node: ScriptBlockNode) -> ScriptBlockNode:
        """Processes script block statements, flattening unpeeled multi-statement blocks."""
        simplified_stmts: List[ASTNode] = []
        for stmt in node.statements:
            res = self.visit(stmt)
            if res is not None:
                # If peeling unmasked a multi-statement ScriptBlock, flatten into parent
                if isinstance(res, ScriptBlockNode) and not node.is_nested:
                    simplified_stmts.extend(res.statements)
                else:
                    simplified_stmts.append(res)
        return ScriptBlockNode(statements=simplified_stmts, is_nested=node.is_nested)

    def visit_command(self, node: CommandNode) -> ASTNode:
        """Inspects and peels CommandNode for direct iex or call-operator invocations."""
        # 1. Direct cmdlet or alias: iex $code / Invoke-Expression $code
        direct_info = self._inspect_direct_iex(node)
        if direct_info is not None:
            vector, invoker, payload_node = direct_info
            peeled = self._peel_payload(payload_node, vector, invoker, depth=1)
            if peeled is not None:
                return self.visit(peeled)

        # 2. Call operator / dot source: & 'iex' $code / . iex $code
        call_info = self._inspect_call_operator_iex(node)
        if call_info is not None:
            vector, invoker, payload_node = call_info
            peeled = self._peel_payload(payload_node, vector, invoker, depth=1)
            if peeled is not None:
                return self.visit(peeled)

        target = self.visit(node.target)
        arguments = [self.visit(a) for a in node.arguments]
        return CommandNode(target=target, arguments=arguments)

    def visit_method_call(self, node: MethodCallNode) -> ASTNode:
        """Inspects and peels ScriptBlock.Create().Invoke() or ExecutionContext invocations."""
        # 1. [scriptblock]::Create($code).Invoke()
        sb_info = self._inspect_scriptblock_create(node)
        if sb_info is not None:
            vector, invoker, payload_node = sb_info
            peeled = self._peel_payload(payload_node, vector, invoker, depth=1)
            if peeled is not None:
                return self.visit(peeled)

        # 2. $ExecutionContext.InvokeCommand.InvokeScript($code)
        ec_info = self._inspect_execution_context(node)
        if ec_info is not None:
            vector, invoker, payload_node = ec_info
            peeled = self._peel_payload(payload_node, vector, invoker, depth=1)
            if peeled is not None:
                return self.visit(peeled)

        target = self.visit(node.target)
        arguments = [self.visit(a) for a in node.arguments]
        return MethodCallNode(target=target, method_name=node.method_name, arguments=arguments)

    def visit_pipeline(self, node: PipelineNode) -> ASTNode:
        """Inspects and peels pipeline IEX stages: $code | iex | iex."""
        elements = [self.visit(e) for e in node.elements]
        if len(elements) < 2:
            return elements[0] if len(elements) == 1 else PipelineNode(elements=elements)

        # Iterate from the rightmost stage to unwrap trailing IEX stages
        while len(elements) >= 2:
            last = elements[-1]
            if self._is_iex_stage(last):
                source = elements[-2]
                invoker = self._get_stage_name(last) or "iex"
                peeled = self._peel_payload(source, vector="pipeline", invoker=invoker, depth=1)
                if peeled is not None:
                    # Replace source with peeled payload and pop the trailing IEX stage
                    elements[-2] = peeled
                    elements.pop()
                    continue
            break

        if len(elements) == 1:
            return elements[0]
        return PipelineNode(elements=elements)

    def _peel_payload(
        self,
        payload_node: ASTNode,
        vector: str,
        invoker: str,
        depth: int,
    ) -> Optional[ASTNode]:
        """
        Recursively unwraps a payload node across nested layers of IEX up to max_depth.
        Handles nested CommandNode, ParenthesizedExpressionNode, StringLiteralNode, and pipelines.
        """
        if depth > self.max_depth:
            return None

        # Unwrap trivial parenthesized wrappers
        curr = payload_node
        while isinstance(curr, ParenthesizedExpressionNode):
            curr = curr.expression

        # Resolve known variables from symbols table if they point to string literals
        if isinstance(curr, VariableNode):
            var_name = curr.name.lower()
            if var_name in self.symbols:
                val = self.symbols[var_name]
                if isinstance(val, str):
                    curr = StringLiteralNode(value=val, is_expandable=False)

        # Case 1: Payload is another CommandNode that is an IEX invocation (e.g., iex (iex $inner))
        if isinstance(curr, CommandNode):
            direct = self._inspect_direct_iex(curr)
            if direct is not None:
                sub_vector, sub_invoker, sub_payload = direct
                inner_peeled = self._peel_payload(sub_payload, sub_vector, sub_invoker, depth + 1)
                if inner_peeled is not None:
                    layer = IEXLayer(
                        layer_index=len(self.last_layers) + 1,
                        vector=vector,
                        invoker=invoker,
                        raw_payload=self._node_to_preview(curr),
                        parsed_ast_type=type(curr).__name__,
                        is_terminal=False,
                    )
                    self.last_layers.append(layer)
                    return inner_peeled
                else:
                    layer = IEXLayer(
                        layer_index=len(self.last_layers) + 1,
                        vector=vector,
                        invoker=invoker,
                        raw_payload=self._node_to_preview(curr),
                        parsed_ast_type=type(curr).__name__,
                        is_terminal=True,
                    )
                    self.last_layers.append(layer)
                    return curr

            call_op = self._inspect_call_operator_iex(curr)
            if call_op is not None:
                sub_vector, sub_invoker, sub_payload = call_op
                inner_peeled = self._peel_payload(sub_payload, sub_vector, sub_invoker, depth + 1)
                if inner_peeled is not None:
                    layer = IEXLayer(
                        layer_index=len(self.last_layers) + 1,
                        vector=vector,
                        invoker=invoker,
                        raw_payload=self._node_to_preview(curr),
                        parsed_ast_type=type(curr).__name__,
                        is_terminal=False,
                    )
                    self.last_layers.append(layer)
                    return inner_peeled
                else:
                    layer = IEXLayer(
                        layer_index=len(self.last_layers) + 1,
                        vector=vector,
                        invoker=invoker,
                        raw_payload=self._node_to_preview(curr),
                        parsed_ast_type=type(curr).__name__,
                        is_terminal=True,
                    )
                    self.last_layers.append(layer)
                    return curr

        # Case 2: Payload is a PipelineNode ending in IEX
        if isinstance(curr, PipelineNode) and len(curr.elements) >= 2 and self._is_iex_stage(curr.elements[-1]):
            layer = IEXLayer(
                layer_index=len(self.last_layers) + 1,
                vector=vector,
                invoker=invoker,
                raw_payload=self._node_to_preview(curr),
                parsed_ast_type=type(curr).__name__,
                is_terminal=False,
            )
            self.last_layers.append(layer)
            return self.visit(curr)

        # Case 3: Payload is a StringLiteralNode containing PowerShell code
        if isinstance(curr, StringLiteralNode):
            code_str = curr.value.strip()
            if not code_str:
                return None

            # Cycle prevention via SHA-256 hash tracking
            h = hashlib.sha256(code_str.encode("utf-8")).hexdigest()
            if h in self.seen_hashes:
                return None
            self.seen_hashes.add(h)

            try:
                sub_lexer = PowerShellLexer(code_str)
                sub_tokens = sub_lexer.tokenize()
                sub_parser = PowerShellParser(sub_tokens)
                parsed = sub_parser.parse()
            except Exception:
                # If parsing fails on raw non-code string, retain as terminal
                return None

            if not parsed.statements:
                return None

            peeled_node: ASTNode
            if len(parsed.statements) == 1:
                peeled_node = parsed.statements[0]
            else:
                peeled_node = parsed

            # Check if parsed node is itself an IEX construct to peel recursively
            is_sub_iex = False
            sub_peeled: Optional[ASTNode] = None

            if isinstance(peeled_node, CommandNode):
                sub_direct = self._inspect_direct_iex(peeled_node)
                if sub_direct is not None:
                    is_sub_iex = True
                    sub_v, sub_inv, sub_arg = sub_direct
                    sub_peeled = self._peel_payload(sub_arg, sub_v, sub_inv, depth + 1)
                else:
                    sub_call = self._inspect_call_operator_iex(peeled_node)
                    if sub_call is not None:
                        is_sub_iex = True
                        sub_v, sub_inv, sub_arg = sub_call
                        sub_peeled = self._peel_payload(sub_arg, sub_v, sub_inv, depth + 1)
            elif isinstance(peeled_node, MethodCallNode):
                sub_sb = self._inspect_scriptblock_create(peeled_node)
                if sub_sb is not None:
                    is_sub_iex = True
                    sub_v, sub_inv, sub_arg = sub_sb
                    sub_peeled = self._peel_payload(sub_arg, sub_v, sub_inv, depth + 1)

            layer = IEXLayer(
                layer_index=len(self.last_layers) + 1,
                vector=vector,
                invoker=invoker,
                raw_payload=code_str,
                parsed_ast_type=type(peeled_node).__name__,
                is_terminal=not is_sub_iex,
            )
            self.last_layers.append(layer)

            if is_sub_iex and sub_peeled is not None:
                return sub_peeled

            return peeled_node

        return None

    def _inspect_direct_iex(self, node: CommandNode) -> Optional[Tuple[str, str, ASTNode]]:
        """Identifies direct iex or Invoke-Expression commands."""
        name = self._get_node_name(node.target)
        if name and name.lower() in self.IEX_NAMES:
            if node.arguments:
                # First argument is the payload expression
                return ("cmdlet", name, node.arguments[0])
        return None

    def _inspect_call_operator_iex(self, node: CommandNode) -> Optional[Tuple[str, str, ASTNode]]:
        """Identifies & 'iex' $code or . 'Invoke-Expression' $code calls."""
        target_name = self._get_node_name(node.target)
        if target_name in ("&", "."):
            if len(node.arguments) >= 2:
                first_arg = node.arguments[0]
                first_name = self._get_node_name(first_arg)
                if first_name and first_name.lower() in self.IEX_NAMES:
                    return ("call_operator", f"{target_name} {first_name}", node.arguments[1])

                # Check alias or variable resolution: $a = 'iex'; &$a $code
                if isinstance(first_arg, VariableNode):
                    var_name = first_arg.name.lower()
                    if var_name in self.symbols:
                        resolved = str(self.symbols[var_name]).lower().strip("'\"")
                        if resolved in self.IEX_NAMES:
                            return ("alias", f"{target_name} ${first_arg.name}", node.arguments[1])
        return None

    def _inspect_scriptblock_create(self, node: MethodCallNode) -> Optional[Tuple[str, str, ASTNode]]:
        """Identifies [scriptblock]::Create($code).Invoke()."""
        method = node.method_name.lower()
        if method in self.SCRIPTBLOCK_METHODS:
            target = node.target
            if isinstance(target, StaticMemberAccessNode):
                clean_type = target.type_name.strip("[]").lower()
                if clean_type in self.SCRIPTBLOCK_TYPES and target.member.lower() == "create":
                    if target.arguments:
                        invoker = f"[{target.type_name}]::Create().{node.method_name}()"
                        return ("scriptblock_create", invoker, target.arguments[0])
        return None

    def _inspect_execution_context(self, node: MethodCallNode) -> Optional[Tuple[str, str, ASTNode]]:
        """Identifies $ExecutionContext.InvokeCommand.InvokeScript($code)."""
        method = node.method_name.lower()
        if method in ("invokescript", "newscriptblock"):
            target = node.target
            if isinstance(target, MemberAccessNode) and target.member.lower() == "invokecommand":
                inner = target.target
                if isinstance(inner, VariableNode) and inner.name.lower() == "executioncontext":
                    if node.arguments:
                        invoker = f"$ExecutionContext.InvokeCommand.{node.method_name}()"
                        return ("execution_context", invoker, node.arguments[0])
        return None

    def _is_iex_stage(self, stage: ASTNode) -> bool:
        """Checks if a pipeline stage is an IEX invocation."""
        name = self._get_stage_name(stage)
        if name and name.lower() in self.IEX_NAMES:
            return True
        if isinstance(stage, CommandNode):
            return self._inspect_direct_iex(stage) is not None or self._inspect_call_operator_iex(stage) is not None
        return False

    def _get_stage_name(self, stage: ASTNode) -> Optional[str]:
        if isinstance(stage, CommandNode):
            return self._get_node_name(stage.target)
        return self._get_node_name(stage)

    def _get_node_name(self, node: ASTNode) -> Optional[str]:
        if isinstance(node, IdentifierNode):
            return node.name.replace("`", "")
        if isinstance(node, StringLiteralNode):
            return node.value.replace("`", "")
        if isinstance(node, ParenthesizedExpressionNode):
            return self._get_node_name(node.expression)
        return None

    def _node_to_preview(self, node: ASTNode) -> str:
        """Returns a concise preview string representation of an AST node."""
        if isinstance(node, StringLiteralNode):
            return node.value
        if isinstance(node, CommandNode):
            tgt = self._get_node_name(node.target) or type(node.target).__name__
            return f"{tgt} (...)"
        return type(node).__name__


def unwrap_iex(
    node: ASTNode,
    symbols: Optional[Dict[str, Any]] = None,
    max_depth: int = 30,
) -> ASTNode:
    """Public helper function to unwrap IEX wrappers on an AST node."""
    unwrapper = PowerShellIEXUnwrapper(symbols=symbols, max_depth=max_depth)
    return unwrapper.unwrap(node)


def trace_iex_layers(
    node: ASTNode,
    symbols: Optional[Dict[str, Any]] = None,
    max_depth: int = 30,
) -> IEXUnwrapResult:
    """Public helper function to trace and extract all IEX wrapper layers with forensic telemetry."""
    unwrapper = PowerShellIEXUnwrapper(symbols=symbols, max_depth=max_depth)
    return unwrapper.unwrap_with_telemetry(node)


def peel_iex_string(
    script: str,
    symbols: Optional[Dict[str, Any]] = None,
    max_depth: int = 30,
) -> str:
    """Convenience helper parsing PowerShell script text, unwrapping IEX layers, and returning normalized source."""
    from .normalizer import PowerShellNormalizer
    lexer = PowerShellLexer(script)
    tokens = lexer.tokenize()
    parser = PowerShellParser(tokens)
    ast = parser.parse()
    unwrapper = PowerShellIEXUnwrapper(symbols=symbols, max_depth=max_depth)
    unwrapped_ast = unwrapper.unwrap(ast)
    normalizer = PowerShellNormalizer(symbols=symbols)
    return normalizer.to_source(unwrapped_ast)
