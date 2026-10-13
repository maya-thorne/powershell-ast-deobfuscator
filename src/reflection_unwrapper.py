"""
PowerShell Reflection & Dynamic Member Invocation Unwrapper.
Statically unwraps .Invoke(), ::Invoke(), GetMethod(), GetMethods(), GetProperty(),
GetField(), and evaluates safe pure .NET methods and dynamic member expressions.
"""

from typing import Any, Dict, List, Optional

from .ast_nodes import (
    ASTNode,
    ArrayLiteralNode,
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
    DynamicMemberAccessNode,
    DynamicMethodCallNode,
    DynamicStaticMemberAccessNode,
    FormatOpNode,
    IdentifierNode,
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
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
)
from .secure_string_crypto import zeroize_buffer
from .type_accelerators import TypeAcceleratorRegistry


class PowerShellReflectionUnwrapper:
    """
    Traverses and transforms PowerShell AST reflection patterns into canonical calls.
    Unwraps:
      - [Type].GetMethod('Name').Invoke($null, @(args)) -> [Type]::Name(args)
      - $inst.GetType().GetMethod('Name').Invoke($inst, @(args)) -> $inst.Name(args)
      - $var.Invoke(...) via symbol table tracking of reflected method definitions
      - [Type].GetProperty('Prop').GetValue($null, $null) -> [Type]::Prop
      - [Type].GetField('Field').GetValue($null) -> [Type]::Field
      - [System.Type]::GetType('FullType') -> [FullType]
      - Dynamic member calls $obj.('Method')(args) -> $obj.Method(args)
      - Safe pure .NET string & math static/instance methods constant folding
    """

    MAX_RECURSION_DEPTH = 10

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols = symbols if symbols is not None else {}
        self.reflection_symbols: Dict[str, Dict[str, Any]] = {}

    def unwrap(self, node: ASTNode) -> ASTNode:
        """Entry point for AST reflection unwrapping and dynamic member resolution."""
        return self.visit(node)

    def visit(self, node: ASTNode) -> ASTNode:
        """Recursive AST dispatcher."""
        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, CommandNode):
            return self.visit_command(node)
        elif isinstance(node, AssignmentNode):
            return self.visit_assignment(node)
        elif isinstance(node, DynamicMemberAccessNode):
            return self.visit_dynamic_member_access(node)
        elif isinstance(node, DynamicMethodCallNode):
            return self.visit_dynamic_method_call(node)
        elif isinstance(node, DynamicStaticMemberAccessNode):
            return self.visit_dynamic_static_member_access(node)
        elif isinstance(node, MethodCallNode):
            return self.visit_method_call(node)
        elif isinstance(node, StaticMemberAccessNode):
            return self.visit_static_member_access(node)
        elif isinstance(node, MemberAccessNode):
            return self.visit_member_access(node)
        elif isinstance(node, ParenthesizedExpressionNode):
            return self.visit_parenthesized(node)
        elif isinstance(node, BinaryOpNode):
            return self.visit_binary_op(node)
        elif isinstance(node, FormatOpNode):
            return self.visit_format_op(node)
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        elif isinstance(node, TypeCastNode):
            return TypeCastNode(type_name=node.type_name, expression=self.visit(node.expression))
        elif isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self.visit(node.target), index=self.visit(node.index))
        elif isinstance(node, RangeExpressionNode):
            return RangeExpressionNode(start=self.visit(node.start), end=self.visit(node.end))
        elif isinstance(node, UnaryOpNode):
            return UnaryOpNode(operator=node.operator, operand=self.visit(node.operand))
        return node

    def visit_script_block(self, node: ScriptBlockNode) -> ScriptBlockNode:
        norm_stmts = [self.visit(s) for s in node.statements]
        return ScriptBlockNode(statements=norm_stmts)

    def visit_pipeline(self, node: PipelineNode) -> ASTNode:
        norm_elements = [self.visit(e) for e in node.elements]
        if len(norm_elements) == 1:
            return norm_elements[0]
        return PipelineNode(elements=norm_elements)

    def visit_command(self, node: CommandNode) -> ASTNode:
        norm_target = self.visit(node.target)
        norm_args = [self.visit(a) for a in node.arguments]
        return CommandNode(target=norm_target, arguments=norm_args)

    def visit_assignment(self, node: AssignmentNode) -> AssignmentNode:
        norm_expr = self.visit(node.expression)
        var_key = node.variable.name.lower()

        # Track reflection method references: $m = [Type].GetMethod('MethodName')
        if isinstance(norm_expr, MethodCallNode):
            meth_lower = norm_expr.method_name.lower()
            if meth_lower == "getmethod" and norm_expr.arguments:
                name = self._extract_string_value(norm_expr.arguments[0])
                if name:
                    self.reflection_symbols[var_key] = {
                        "kind": "method",
                        "target": norm_expr.target,
                        "name": name,
                    }
            elif meth_lower == "getproperty" and norm_expr.arguments:
                name = self._extract_string_value(norm_expr.arguments[0])
                if name:
                    self.reflection_symbols[var_key] = {
                        "kind": "property",
                        "target": norm_expr.target,
                        "name": name,
                    }
            elif meth_lower == "getfield" and norm_expr.arguments:
                name = self._extract_string_value(norm_expr.arguments[0])
                if name:
                    self.reflection_symbols[var_key] = {
                        "kind": "field",
                        "target": norm_expr.target,
                        "name": name,
                    }
        elif isinstance(norm_expr, StaticMemberAccessNode):
            if norm_expr.type_name.strip("[]") in ("System.Type", "Type") and norm_expr.member.lower() == "gettype":
                if norm_expr.arguments:
                    type_str = self._extract_string_value(norm_expr.arguments[0])
                    if type_str:
                        resolved = TypeAcceleratorRegistry.resolve_full_type(type_str)
                        self.reflection_symbols[var_key] = {
                            "kind": "type",
                            "name": resolved,
                        }

        return AssignmentNode(variable=node.variable, expression=norm_expr)

    def visit_dynamic_member_access(self, node: DynamicMemberAccessNode) -> ASTNode:
        target = self.visit(node.target)
        member_expr = self.visit(node.member_expr)
        member_name = self._extract_string_value(member_expr)
        if member_name:
            return self.visit_member_access(MemberAccessNode(target=target, member=member_name))
        return DynamicMemberAccessNode(target=target, member_expr=member_expr)

    def visit_dynamic_method_call(self, node: DynamicMethodCallNode) -> ASTNode:
        target = self.visit(node.target)
        method_expr = self.visit(node.method_expr)
        arguments = [self.visit(a) for a in node.arguments]
        method_name = self._extract_string_value(method_expr)
        if method_name:
            return self.visit_method_call(MethodCallNode(target=target, method_name=method_name, arguments=arguments))
        return DynamicMethodCallNode(target=target, method_expr=method_expr, arguments=arguments)

    def visit_dynamic_static_member_access(self, node: DynamicStaticMemberAccessNode) -> ASTNode:
        type_name = self._clean_type_name(node.type_name)
        member_expr = self.visit(node.member_expr)
        arguments = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
        member_name = self._extract_string_value(member_expr)
        if member_name:
            return self.visit_static_member_access(StaticMemberAccessNode(type_name=type_name, member=member_name, arguments=arguments))
        return DynamicStaticMemberAccessNode(type_name=type_name, member_expr=member_expr, arguments=arguments)

    def visit_method_call(self, node: MethodCallNode) -> ASTNode:
        target = self.visit(node.target)
        method_name = node.method_name
        arguments = [self.visit(a) for a in node.arguments]
        meth_lower = method_name.lower()

        # 1. Direct Chained Reflection: target.GetMethod('Method').Invoke($null, @(args))
        if meth_lower == "invoke":
            unwrapped = self._try_unwrap_invoke(target, arguments)
            if unwrapped is not None:
                return unwrapped

        # 2. Direct Chained Reflection Property / Field: target.GetProperty('Prop').GetValue(...)
        if meth_lower == "getvalue":
            unwrapped = self._try_unwrap_getvalue(target, arguments)
            if unwrapped is not None:
                return unwrapped

        # 3. Direct Chained Reflection Property / Field: target.GetField('Field').SetValue(...)
        if meth_lower == "setvalue":
            unwrapped = self._try_unwrap_setvalue(target, arguments)
            if unwrapped is not None:
                return unwrapped

        # 4. Pure String Instance Methods Evaluation
        if isinstance(target, StringLiteralNode):
            evaluated = self._evaluate_string_method(target, meth_lower, arguments)
            if evaluated is not None:
                return evaluated

        return MethodCallNode(target=target, method_name=method_name, arguments=arguments)

    def visit_static_member_access(self, node: StaticMemberAccessNode) -> ASTNode:
        type_name = self._clean_type_name(node.type_name)
        member = node.member
        norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None

        # Static .Invoke() on delegates or scriptblocks
        if member.lower() == "invoke" and norm_args is not None:
            if type_name in ("System.Management.Automation.ScriptBlock", "ScriptBlock"):
                if norm_args and isinstance(norm_args[0], StringLiteralNode):
                    return CommandNode(target=IdentifierNode(name="&"), arguments=[norm_args[0]])

        # [System.Type]::GetType('FullType')
        if type_name in ("System.Type", "Type") and member.lower() == "gettype" and norm_args:
            type_str = self._extract_string_value(norm_args[0])
            if type_str:
                resolved = TypeAcceleratorRegistry.resolve_full_type(type_str)
                return IdentifierNode(name=f"[{resolved}]")

        # [System.String] pure static methods evaluation
        if type_name in ("System.String", "String") and norm_args is not None:
            evaluated = self._evaluate_static_string_method(member.lower(), norm_args)
            if evaluated is not None:
                return evaluated

        # [System.Math] pure static methods evaluation
        if type_name in ("System.Math", "Math") and norm_args is not None:
            evaluated = self._evaluate_static_math_method(member.lower(), norm_args)
            if evaluated is not None:
                return evaluated

        return StaticMemberAccessNode(type_name=type_name, member=member, arguments=norm_args)

    def visit_member_access(self, node: MemberAccessNode) -> ASTNode:
        target = self.visit(node.target)
        member = node.member

        # String length: 'hello'.Length -> 5
        if isinstance(target, StringLiteralNode) and member.lower() == "length":
            val = len(target.value)
            return NumberLiteralNode(value=val, raw=str(val))

        # Array length: @(1, 2, 3).Length -> 3 or .Count -> 3
        if isinstance(target, ArrayLiteralNode) and member.lower() in ("length", "count"):
            val = len(target.elements)
            return NumberLiteralNode(value=val, raw=str(val))

        # Type reflection metadata: [System.String].Name -> 'String'
        if isinstance(target, IdentifierNode) and target.name.startswith("[") and target.name.endswith("]"):
            metadata = TypeAcceleratorRegistry.get_type_metadata(target.name)
            if member in metadata:
                return StringLiteralNode(value=metadata[member], is_expandable=False)

        # Instance GetType() reflection metadata: 'test'.GetType().Name -> 'String'
        if isinstance(target, MethodCallNode) and target.method_name.lower() == "gettype":
            inner_target = target.target
            if isinstance(inner_target, StringLiteralNode):
                meta = TypeAcceleratorRegistry.get_type_metadata("[string]")
                if member in meta:
                    return StringLiteralNode(value=meta[member], is_expandable=False)
            elif isinstance(inner_target, NumberLiteralNode):
                meta = TypeAcceleratorRegistry.get_type_metadata("[int]")
                if member in meta:
                    return StringLiteralNode(value=meta[member], is_expandable=False)
            elif isinstance(inner_target, ArrayLiteralNode):
                meta = TypeAcceleratorRegistry.get_type_metadata("[array]")
                if member in meta:
                    return StringLiteralNode(value=meta[member], is_expandable=False)

        return MemberAccessNode(target=target, member=member)

    def visit_parenthesized(self, node: ParenthesizedExpressionNode) -> ASTNode:
        norm_inner = self.visit(node.expression)
        if isinstance(norm_inner, (StringLiteralNode, NumberLiteralNode, IdentifierNode)):
            return norm_inner
        return ParenthesizedExpressionNode(expression=norm_inner)

    def visit_binary_op(self, node: BinaryOpNode) -> ASTNode:
        left = self.visit(node.left)
        right = self.visit(node.right)
        if node.operator == "+" and isinstance(left, StringLiteralNode) and isinstance(right, StringLiteralNode):
            return StringLiteralNode(value=left.value + right.value, is_expandable=left.is_expandable or right.is_expandable)
        return BinaryOpNode(left=left, operator=node.operator, right=right)

    def visit_format_op(self, node: FormatOpNode) -> ASTNode:
        norm_fmt = self.visit(node.format_string)
        norm_args = [self.visit(a) for a in node.arguments]
        return FormatOpNode(format_string=norm_fmt, arguments=norm_args)

    # -------------------------------------------------------------------------
    # Internal Unwrapping & Reduction Engines
    # -------------------------------------------------------------------------

    def _try_unwrap_invoke(self, target: ASTNode, arguments: List[ASTNode]) -> Optional[ASTNode]:
        """Attempts unwrapping a .Invoke(...) method invocation on reflection targets."""
        # A. Target is direct GetMethod(...) call
        if isinstance(target, MethodCallNode) and target.method_name.lower() == "getmethod":
            if target.arguments:
                reflected_name = self._extract_string_value(target.arguments[0])
                if reflected_name:
                    return self._dispatch_reflected_call(target.target, reflected_name, arguments)

        # B. Target is variable reference tracked in reflection symbols
        if isinstance(target, VariableNode):
            var_key = target.name.lower()
            if var_key in self.reflection_symbols:
                info = self.reflection_symbols[var_key]
                if info["kind"] == "method":
                    return self._dispatch_reflected_call(info["target"], info["name"], arguments)

        # C. Target is inline ScriptBlock: { ... }.Invoke()
        inner_sb = None
        if isinstance(target, ScriptBlockNode):
            inner_sb = target
        elif isinstance(target, ParenthesizedExpressionNode) and isinstance(target.expression, ScriptBlockNode):
            inner_sb = target.expression

        if inner_sb is not None:
            if not arguments and len(inner_sb.statements) == 1:
                return inner_sb.statements[0]
            return CommandNode(target=IdentifierNode(name="&"), arguments=[target] + arguments)

        return None

    def _dispatch_reflected_call(self, ref_target: ASTNode, method_name: str, invoke_args: List[ASTNode]) -> ASTNode:
        """Dispatches an unwrapped reflection method call to static or instance target."""
        if len(invoke_args) >= 2:
            inv_target = invoke_args[0]
            unpacked_args = self._unpack_invoke_arguments(invoke_args[1])
        elif len(invoke_args) == 1:
            inv_target = invoke_args[0]
            unpacked_args = []
        else:
            inv_target = None
            unpacked_args = []

        # If invocation target is $null, it is a static method call on ref_target
        if inv_target is None or self._is_null_node(inv_target):
            type_name = self._extract_type_name(ref_target)
            if type_name:
                unwrapped = StaticMemberAccessNode(type_name=type_name, member=method_name, arguments=unpacked_args)
                return self.visit_static_member_access(unwrapped)
            else:
                unwrapped = MethodCallNode(target=ref_target, method_name=method_name, arguments=unpacked_args)
                return self.visit_method_call(unwrapped)
        else:
            # Instance method call on inv_target
            unwrapped = MethodCallNode(target=inv_target, method_name=method_name, arguments=unpacked_args)
            return self.visit_method_call(unwrapped)

    def _try_unwrap_getvalue(self, target: ASTNode, arguments: List[ASTNode]) -> Optional[ASTNode]:
        """Attempts unwrapping a .GetValue(...) call on reflection property or field."""
        prop_or_field = None
        ref_target = None

        if isinstance(target, MethodCallNode) and target.method_name.lower() in ("getproperty", "getfield"):
            if target.arguments:
                prop_or_field = self._extract_string_value(target.arguments[0])
                ref_target = target.target

        elif isinstance(target, VariableNode):
            var_key = target.name.lower()
            if var_key in self.reflection_symbols:
                info = self.reflection_symbols[var_key]
                if info["kind"] in ("property", "field"):
                    prop_or_field = info["name"]
                    ref_target = info["target"]

        if prop_or_field and ref_target:
            inv_target = arguments[0] if arguments else None
            if inv_target is None or self._is_null_node(inv_target):
                type_name = self._extract_type_name(ref_target)
                if type_name:
                    return StaticMemberAccessNode(type_name=type_name, member=prop_or_field, arguments=None)
            else:
                return MemberAccessNode(target=inv_target, member=prop_or_field)

        return None

    def _try_unwrap_setvalue(self, target: ASTNode, arguments: List[ASTNode]) -> Optional[ASTNode]:
        """Attempts unwrapping a .SetValue(...) call on reflection property or field."""
        prop_or_field = None
        ref_target = None

        if isinstance(target, MethodCallNode) and target.method_name.lower() in ("getproperty", "getfield"):
            if target.arguments:
                prop_or_field = self._extract_string_value(target.arguments[0])
                ref_target = target.target

        elif isinstance(target, VariableNode):
            var_key = target.name.lower()
            if var_key in self.reflection_symbols:
                info = self.reflection_symbols[var_key]
                if info["kind"] in ("property", "field"):
                    prop_or_field = info["name"]
                    ref_target = info["target"]

        if prop_or_field and ref_target and len(arguments) >= 2:
            inv_target = arguments[0]
            val = arguments[1]
            if inv_target is None or self._is_null_node(inv_target):
                type_name = self._extract_type_name(ref_target)
                if type_name:
                    left_node = StaticMemberAccessNode(type_name=type_name, member=prop_or_field, arguments=None)
                    return BinaryOpNode(left=left_node, operator="=", right=val)
            else:
                left_node = MemberAccessNode(target=inv_target, member=prop_or_field)
                return BinaryOpNode(left=left_node, operator="=", right=val)

        return None

    def _evaluate_string_method(self, target: StringLiteralNode, meth: str, args: List[ASTNode]) -> Optional[ASTNode]:
        """Statically evaluates pure instance string methods with safety bounds checks."""
        val = target.value
        exp = target.is_expandable

        if meth == "substring":
            if len(args) == 1 and isinstance(args[0], NumberLiteralNode):
                start = int(args[0].value)
                if 0 <= start <= len(val):
                    return StringLiteralNode(value=val[start:], is_expandable=exp)
            elif len(args) == 2 and isinstance(args[0], NumberLiteralNode) and isinstance(args[1], NumberLiteralNode):
                start = int(args[0].value)
                cnt = int(args[1].value)
                if 0 <= start <= len(val) and 0 <= start + cnt <= len(val) and cnt >= 0:
                    return StringLiteralNode(value=val[start:start + cnt], is_expandable=exp)

        elif meth in ("tolower", "tolowerinvariant"):
            return StringLiteralNode(value=val.lower(), is_expandable=exp)

        elif meth in ("toupper", "toupperinvariant"):
            return StringLiteralNode(value=val.upper(), is_expandable=exp)

        elif meth == "trim":
            return StringLiteralNode(value=val.strip(), is_expandable=exp)

        elif meth == "trimstart":
            return StringLiteralNode(value=val.lstrip(), is_expandable=exp)

        elif meth == "trimend":
            return StringLiteralNode(value=val.rstrip(), is_expandable=exp)

        elif meth == "replace" and len(args) == 2:
            s_old = self._extract_string_value(args[0])
            s_new = self._extract_string_value(args[1])
            if s_old is not None and s_new is not None:
                return StringLiteralNode(value=val.replace(s_old, s_new), is_expandable=exp)

        elif meth == "split" and len(args) == 1:
            delim = self._extract_string_value(args[0])
            if delim is not None:
                parts = val.split(delim)
                return ArrayLiteralNode(elements=[StringLiteralNode(value=p, is_expandable=exp) for p in parts])

        elif meth == "contains" and len(args) == 1:
            sub = self._extract_string_value(args[0])
            if sub is not None:
                res = sub.lower() in val.lower()
                return IdentifierNode(name="$true" if res else "$false")

        elif meth == "startswith" and len(args) == 1:
            sub = self._extract_string_value(args[0])
            if sub is not None:
                res = val.lower().startswith(sub.lower())
                return IdentifierNode(name="$true" if res else "$false")

        elif meth == "endswith" and len(args) == 1:
            sub = self._extract_string_value(args[0])
            if sub is not None:
                res = val.lower().endswith(sub.lower())
                return IdentifierNode(name="$true" if res else "$false")

        elif meth == "indexof" and len(args) == 1:
            sub = self._extract_string_value(args[0])
            if sub is not None:
                idx = val.find(sub)
                return NumberLiteralNode(value=idx, raw=str(idx))

        elif meth == "lastindexof" and len(args) == 1:
            sub = self._extract_string_value(args[0])
            if sub is not None:
                idx = val.rfind(sub)
                return NumberLiteralNode(value=idx, raw=str(idx))

        elif meth == "padleft":
            if len(args) == 1 and isinstance(args[0], NumberLiteralNode):
                w = int(args[0].value)
                if 0 <= w <= 4096:
                    return StringLiteralNode(value=val.rjust(w), is_expandable=exp)
            elif len(args) == 2 and isinstance(args[0], NumberLiteralNode):
                w = int(args[0].value)
                ch = self._extract_string_value(args[1]) or " "
                if 0 <= w <= 4096:
                    return StringLiteralNode(value=val.rjust(w, ch[0]), is_expandable=exp)

        elif meth == "padright":
            if len(args) == 1 and isinstance(args[0], NumberLiteralNode):
                w = int(args[0].value)
                if 0 <= w <= 4096:
                    return StringLiteralNode(value=val.ljust(w), is_expandable=exp)
            elif len(args) == 2 and isinstance(args[0], NumberLiteralNode):
                w = int(args[0].value)
                ch = self._extract_string_value(args[1]) or " "
                if 0 <= w <= 4096:
                    return StringLiteralNode(value=val.ljust(w, ch[0]), is_expandable=exp)

        elif meth == "insert" and len(args) == 2 and isinstance(args[0], NumberLiteralNode):
            idx = int(args[0].value)
            s_ins = self._extract_string_value(args[1])
            if s_ins is not None and 0 <= idx <= len(val):
                return StringLiteralNode(value=val[:idx] + s_ins + val[idx:], is_expandable=exp)

        elif meth == "remove":
            if len(args) == 1 and isinstance(args[0], NumberLiteralNode):
                start = int(args[0].value)
                if 0 <= start <= len(val):
                    return StringLiteralNode(value=val[:start], is_expandable=exp)
            elif len(args) == 2 and isinstance(args[0], NumberLiteralNode) and isinstance(args[1], NumberLiteralNode):
                start = int(args[0].value)
                cnt = int(args[1].value)
                if 0 <= start <= len(val) and 0 <= start + cnt <= len(val) and cnt >= 0:
                    return StringLiteralNode(value=val[:start] + val[start + cnt:], is_expandable=exp)

        elif meth == "tostring":
            return target

        return None

    def _evaluate_static_string_method(self, meth: str, args: List[ASTNode]) -> Optional[ASTNode]:
        """Statically evaluates pure [System.String] static methods."""
        if meth == "concat":
            if all(isinstance(a, (StringLiteralNode, NumberLiteralNode)) for a in args):
                res = "".join(str(a.value) for a in args)
                return StringLiteralNode(value=res, is_expandable=False)
        elif meth == "join" and len(args) >= 2:
            delim = self._extract_string_value(args[0])
            if delim is not None:
                elements = self._extract_element_list(args[1])
                if elements is not None and all(isinstance(e, (StringLiteralNode, NumberLiteralNode)) for e in elements):
                    res = delim.join(str(e.value) for e in elements)
                    return StringLiteralNode(value=res, is_expandable=False)
        elif meth == "isnullorempty" and len(args) == 1:
            s = self._extract_string_value(args[0])
            if s is not None:
                res = len(s) == 0
                return IdentifierNode(name="$true" if res else "$false")
        elif meth == "isnullorwhitespace" and len(args) == 1:
            s = self._extract_string_value(args[0])
            if s is not None:
                res = len(s.strip()) == 0
                return IdentifierNode(name="$true" if res else "$false")
        return None

    def _evaluate_static_math_method(self, meth: str, args: List[ASTNode]) -> Optional[ASTNode]:
        """Statically evaluates pure [System.Math] static methods."""
        if meth == "abs" and len(args) == 1 and isinstance(args[0], NumberLiteralNode):
            v = abs(args[0].value)
            return NumberLiteralNode(value=v, raw=str(v))
        elif meth == "max" and len(args) == 2 and isinstance(args[0], NumberLiteralNode) and isinstance(args[1], NumberLiteralNode):
            v = max(args[0].value, args[1].value)
            return NumberLiteralNode(value=v, raw=str(v))
        elif meth == "min" and len(args) == 2 and isinstance(args[0], NumberLiteralNode) and isinstance(args[1], NumberLiteralNode):
            v = min(args[0].value, args[1].value)
            return NumberLiteralNode(value=v, raw=str(v))
        return None

    # -------------------------------------------------------------------------
    # Helper Utilities
    # -------------------------------------------------------------------------

    def _extract_string_value(self, node: ASTNode) -> Optional[str]:
        """Extracts constant string value from string literals or parenthesized nodes."""
        if isinstance(node, StringLiteralNode):
            return node.value
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_string_value(node.expression)
        if isinstance(node, VariableNode):
            val = self.symbols.get(node.name.lower())
            if isinstance(val, str):
                return val
        return None

    def _extract_element_list(self, node: ASTNode) -> Optional[List[ASTNode]]:
        """Extracts elements from array literals or type cast arrays."""
        if isinstance(node, ArrayLiteralNode):
            return node.elements
        if isinstance(node, TypeCastNode):
            return self._extract_element_list(node.expression)
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_element_list(node.expression)
        return None

    def _unpack_invoke_arguments(self, node: ASTNode) -> List[ASTNode]:
        """Unpacks reflection invoke arguments array into a clean parameter list."""
        if self._is_null_node(node):
            return []
        if isinstance(node, ParenthesizedExpressionNode):
            return self._unpack_invoke_arguments(node.expression)
        if isinstance(node, TypeCastNode):
            return self._unpack_invoke_arguments(node.expression)
        if isinstance(node, ArrayLiteralNode):
            return node.elements
        return [node]

    def _is_null_node(self, node: Optional[ASTNode]) -> bool:
        """Checks if AST node represents $null or None."""
        if node is None:
            return True
        if isinstance(node, VariableNode) and node.name.lower() == "null":
            return True
        if isinstance(node, IdentifierNode) and node.name.lower() == "$null":
            return True
        return False

    def _extract_type_name(self, node: ASTNode) -> Optional[str]:
        """Extracts .NET type name from AST node representing a type."""
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_type_name(node.expression)
        if isinstance(node, TypeCastNode):
            if TypeAcceleratorRegistry.get_canonical_alias(node.type_name).lower() == "type":
                type_str = self._extract_string_value(node.expression)
                if type_str:
                    return self._clean_type_name(type_str)
            return self._clean_type_name(node.type_name)
        if isinstance(node, IdentifierNode):
            return self._clean_type_name(node.name)
        if isinstance(node, MethodCallNode) and node.method_name.lower() == "gettype":
            return self._extract_type_name(node.target)
        if isinstance(node, VariableNode):
            var_key = node.name.lower()
            if var_key in self.reflection_symbols and self.reflection_symbols[var_key]["kind"] == "type":
                return self.reflection_symbols[var_key]["name"]
        return None

    def _clean_type_name(self, name: str) -> str:
        """Strips surrounding brackets and normalizes type accelerator names."""
        clean = name.strip("[]")
        return TypeAcceleratorRegistry.resolve_full_type(clean)
