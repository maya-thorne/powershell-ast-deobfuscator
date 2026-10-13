"""
PowerShell AST Normalizer & Constant Folder.
Transforms obfuscated AST constructs into readable, simplified standard syntax.
"""

import re
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
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)
from .environment_inliner import PowerShellEnvironmentInliner
from .pipeline_optimizer import PowerShellPipelineOptimizer
from .reflection_unwrapper import PowerShellReflectionUnwrapper
from .scriptblock_simplifier import PowerShellScriptBlockSimplifier
from .secure_string_reducer import PowerShellSecureStringReducer
from .type_casting_resolver import PowerShellTypeCastingResolver


class PowerShellNormalizer:
    """
    Traverses and normalizes PowerShell AST nodes.
    Folds string concatenations, formats '-f' templates, inlines environment variables
    and ExecutionContext properties, resolves SecureString unboxing patterns,
    type accelerators, char/byte casts, reflection unboxing, pipeline stages,
    control flow branches, and strips backtick evasion artifacts.
    """

    def __init__(self, symbols: Optional[Dict[str, Any]] = None, env: Optional[Dict[str, str]] = None):
        self.symbols = symbols if symbols is not None else {}
        self.env_inliner = PowerShellEnvironmentInliner(symbols=self.symbols, env=env)
        self.sec_reducer = PowerShellSecureStringReducer(symbols=self.symbols)
        self.type_resolver = PowerShellTypeCastingResolver(symbols=self.symbols)
        self.refl_unwrapper = PowerShellReflectionUnwrapper(symbols=self.symbols)
        self.pipe_optimizer = PowerShellPipelineOptimizer(symbols=self.symbols)
        self.sb_simplifier = PowerShellScriptBlockSimplifier(symbols=self.symbols)

    def normalize(self, node: ASTNode) -> ASTNode:
        # Pass 1: Inline environment variables & ExecutionContext methods
        node = self.env_inliner.inline(node)
        # Pass 2: Reduce SecureString operations
        node = self.sec_reducer.reduce(node)
        # Pass 3: Resolve type accelerators, char/byte casts & array shuffling
        node = self.type_resolver.resolve(node)
        # Pass 4: Reflection & dynamic member unwrapping
        node = self.refl_unwrapper.unwrap(node)
        # Pass 5: Pipeline stage optimization (| %, | select, | where)
        node = self.pipe_optimizer.optimize(node)
        # Pass 6: ScriptBlock & control flow simplification (& { ... }, if ($true))
        node = self.sb_simplifier.simplify(node)
        # Pass 7: Canonical AST normalizations (folding, backticks)
        node = self.visit(node)
        # Pass 8: Cascading convergence passes
        node = self.pipe_optimizer.optimize(node)
        node = self.type_resolver.resolve(node)
        node = self.sb_simplifier.simplify(node)
        node = self.env_inliner.inline(node)
        node = self.refl_unwrapper.unwrap(node)
        node = self.sec_reducer.reduce(node)
        return node

    def visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, CommandNode):
            return self.visit_command(node)
        elif isinstance(node, FormatOpNode):
            return self.visit_format_op(node)
        elif isinstance(node, BinaryOpNode):
            return self.visit_binary_op(node)
        elif isinstance(node, ParenthesizedExpressionNode):
            return self.visit_parenthesized(node)
        elif isinstance(node, AssignmentNode):
            return self.visit_assignment(node)
        elif isinstance(node, StringLiteralNode):
            return self.visit_string_literal(node)
        elif isinstance(node, IdentifierNode):
            return self.visit_identifier(node)
        elif isinstance(node, RangeExpressionNode):
            return RangeExpressionNode(self.visit(node.start), self.visit(node.end))
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        elif isinstance(node, TypeCastNode):
            return TypeCastNode(type_name=node.type_name, expression=self.visit(node.expression))
        elif isinstance(node, MemberAccessNode):
            return MemberAccessNode(target=self.visit(node.target), member=node.member)
        elif isinstance(node, StaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)
        elif isinstance(node, MethodCallNode):
            norm_target = self.visit(node.target)
            norm_args = [self.visit(a) for a in node.arguments]
            return MethodCallNode(target=norm_target, method_name=node.method_name, arguments=norm_args)
        elif isinstance(node, UnaryOpNode):
            return UnaryOpNode(operator=node.operator, operand=self.visit(node.operand))
        elif isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self.visit(node.target), index=self.visit(node.index))
        elif isinstance(node, DynamicMemberAccessNode):
            norm_target = self.visit(node.target)
            norm_expr = self.visit(node.member_expr)
            if isinstance(norm_expr, StringLiteralNode):
                return MemberAccessNode(target=norm_target, member=norm_expr.value)
            return DynamicMemberAccessNode(target=norm_target, member_expr=norm_expr)
        elif isinstance(node, DynamicMethodCallNode):
            norm_target = self.visit(node.target)
            norm_expr = self.visit(node.method_expr)
            norm_args = [self.visit(a) for a in node.arguments]
            if isinstance(norm_expr, StringLiteralNode):
                return MethodCallNode(target=norm_target, method_name=norm_expr.value, arguments=norm_args)
            return DynamicMethodCallNode(target=norm_target, method_expr=norm_expr, arguments=norm_args)
        elif isinstance(node, DynamicStaticMemberAccessNode):
            norm_expr = self.visit(node.member_expr)
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            clean_type = node.type_name.strip("[]")
            if isinstance(norm_expr, StringLiteralNode):
                return StaticMemberAccessNode(type_name=clean_type, member=norm_expr.value, arguments=norm_args)
            return DynamicStaticMemberAccessNode(type_name=clean_type, member_expr=norm_expr, arguments=norm_args)
        elif isinstance(node, IfStatementNode):
            return IfStatementNode(
                condition=self.visit(node.condition),
                then_branch=self.visit(node.then_branch),
                else_branch=self.visit(node.else_branch) if node.else_branch else None,
            )
        elif isinstance(node, WhileStatementNode):
            return WhileStatementNode(condition=self.visit(node.condition), body=self.visit(node.body))
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

        if isinstance(norm_target, IdentifierNode) and norm_target.name in ("&", "."):
            if norm_args:
                first_arg = norm_args[0]
                inner_arg = first_arg.expression if isinstance(first_arg, ParenthesizedExpressionNode) else first_arg
                if isinstance(inner_arg, StringLiteralNode):
                    cmd_val = inner_arg.value.strip()
                    if re.match(r"^[A-Za-z0-9_.-]+$", cmd_val):
                        return CommandNode(
                            target=IdentifierNode(name=cmd_val),
                            arguments=norm_args[1:],
                        )
                elif isinstance(inner_arg, ScriptBlockNode) and len(norm_args) == 1:
                    if len(inner_arg.statements) == 1:
                        return inner_arg.statements[0]
                    return inner_arg

        return CommandNode(target=norm_target, arguments=norm_args)

    def visit_parenthesized(self, node: ParenthesizedExpressionNode) -> ASTNode:
        norm_inner = self.visit(node.expression)
        # Unwrap trivial string literals or numbers from parentheses
        if isinstance(norm_inner, (StringLiteralNode, NumberLiteralNode, IdentifierNode)):
            return norm_inner
        return ParenthesizedExpressionNode(expression=norm_inner)

    def visit_string_literal(self, node: StringLiteralNode) -> StringLiteralNode:
        clean_val = node.value.replace("`", "")
        return StringLiteralNode(value=clean_val, is_expandable=node.is_expandable)

    def visit_identifier(self, node: IdentifierNode) -> IdentifierNode:
        clean_name = node.name.replace("`", "")
        return IdentifierNode(name=clean_name)

    def visit_binary_op(self, node: BinaryOpNode) -> ASTNode:
        left = self.visit(node.left)
        right = self.visit(node.right)

        # Constant folding for string concatenation: 'a' + 'b' -> 'ab'
        if node.operator == "+":
            if isinstance(left, StringLiteralNode) and isinstance(right, StringLiteralNode):
                return StringLiteralNode(
                    value=left.value + right.value,
                    is_expandable=left.is_expandable or right.is_expandable,
                )
            if isinstance(left, NumberLiteralNode) and isinstance(right, NumberLiteralNode):
                return NumberLiteralNode(
                    value=left.value + right.value,
                    raw=str(left.value + right.value),
                )

        # Numeric constant folding for arithmetic and bitwise operators
        if isinstance(left, NumberLiteralNode) and isinstance(right, NumberLiteralNode):
            try:
                l_val = int(left.value)
                r_val = int(right.value)
                op = node.operator.lower()
                if op == "-":
                    res = l_val - r_val
                    return NumberLiteralNode(value=res, raw=str(res))
                elif op == "*":
                    res = l_val * r_val
                    return NumberLiteralNode(value=res, raw=str(res))
                elif op == "-bxor":
                    res = l_val ^ r_val
                    return NumberLiteralNode(value=res, raw=str(res))
                elif op == "-band":
                    res = l_val & r_val
                    return NumberLiteralNode(value=res, raw=str(res))
                elif op == "-bor":
                    res = l_val | r_val
                    return NumberLiteralNode(value=res, raw=str(res))
                elif op == "-shl":
                    res = l_val << r_val
                    return NumberLiteralNode(value=res, raw=str(res))
                elif op == "-shr":
                    res = l_val >> r_val
                    return NumberLiteralNode(value=res, raw=str(res))
            except (ValueError, OverflowError):
                pass

        return BinaryOpNode(left=left, operator=node.operator, right=right)

    def visit_format_op(self, node: FormatOpNode) -> ASTNode:
        norm_fmt = self.visit(node.format_string)
        norm_args = [self.visit(a) for a in node.arguments]

        # Constant folding for '-f' operator
        if isinstance(norm_fmt, StringLiteralNode):
            # Check if all arguments are string or number literals
            all_literals = all(isinstance(a, (StringLiteralNode, NumberLiteralNode)) for a in norm_args)
            if all_literals:
                arg_values = [str(a.value) for a in norm_args]
                template = norm_fmt.value

                # Evaluate {0}, {1}, etc. placeholders
                def replace_placeholder(match: re.Match) -> str:
                    idx_str = match.group(1)
                    idx = int(idx_str)
                    if 0 <= idx < len(arg_values):
                        return arg_values[idx]
                    return match.group(0)

                result = re.sub(r"\{(\d+)\}", replace_placeholder, template)
                return StringLiteralNode(value=result, is_expandable=norm_fmt.is_expandable)

        return FormatOpNode(format_string=norm_fmt, arguments=norm_args)

    def visit_assignment(self, node: AssignmentNode) -> AssignmentNode:
        norm_expr = self.visit(node.expression)
        if isinstance(norm_expr, StringLiteralNode):
            self.symbols[node.variable.name.lower()] = norm_expr.value
        return AssignmentNode(variable=node.variable, expression=norm_expr)

    def to_source(self, node: ASTNode) -> str:
        """Serializes normalized AST back into canonical PowerShell code string."""
        if isinstance(node, ScriptBlockNode):
            if node.is_nested:
                inner = "; ".join(self.to_source(s) for s in node.statements)
                return f"{{ {inner} }}"
            return "\n".join(self.to_source(s) for s in node.statements)

        if isinstance(node, PipelineNode):
            return " | ".join(self.to_source(e) for e in node.elements)

        if isinstance(node, CommandNode):
            target_str = self.to_source(node.target)
            args_str = " ".join(self.to_source(a) for a in node.arguments)
            return f"{target_str} {args_str}".strip()

        if isinstance(node, StringLiteralNode):
            if node.is_expandable:
                escaped = node.value.replace('"', '`"')
                return f'"{escaped}"'
            else:
                escaped = node.value.replace("'", "''")
                return f"'{escaped}'"

        if isinstance(node, NumberLiteralNode):
            return str(node.value)

        if isinstance(node, VariableNode):
            if node.scope:
                return f"${node.scope}:{node.name}"
            return f"${node.name}"

        if isinstance(node, IdentifierNode):
            return node.name

        if isinstance(node, BinaryOpNode):
            left_str = self.to_source(node.left)
            right_str = self.to_source(node.right)
            return f"{left_str} {node.operator} {right_str}"

        if isinstance(node, FormatOpNode):
            fmt_str = self.to_source(node.format_string)
            args_str = ", ".join(self.to_source(a) for a in node.arguments)
            return f"{fmt_str} -f {args_str}"

        if isinstance(node, AssignmentNode):
            if node.variable.scope:
                return f"${node.variable.scope}:{node.variable.name} = {self.to_source(node.expression)}"
            return f"${node.variable.name} = {self.to_source(node.expression)}"

        if isinstance(node, ParenthesizedExpressionNode):
            if isinstance(node.expression, (StringLiteralNode, NumberLiteralNode, IdentifierNode)):
                return self.to_source(node.expression)
            return f"({self.to_source(node.expression)})"

        if isinstance(node, RangeExpressionNode):
            return f"{self.to_source(node.start)}..{self.to_source(node.end)}"

        if isinstance(node, ArrayLiteralNode):
            elements_str = ", ".join(self.to_source(e) for e in node.elements)
            return f"@({elements_str})"

        if isinstance(node, TypeCastNode):
            return f"[{node.type_name}]({self.to_source(node.expression)})"

        if isinstance(node, MemberAccessNode):
            target_str = self.to_source(node.target)
            return f"{target_str}.{node.member}"

        if isinstance(node, StaticMemberAccessNode):
            clean_type = node.type_name.strip("[]")
            if node.arguments is not None:
                args_str = ", ".join(self.to_source(a) for a in node.arguments)
                return f"[{clean_type}]::{node.member}({args_str})"
            return f"[{clean_type}]::{node.member}"

        if isinstance(node, MethodCallNode):
            target_str = self.to_source(node.target)
            args_str = ", ".join(self.to_source(a) for a in node.arguments)
            return f"{target_str}.{node.method_name}({args_str})"

        if isinstance(node, DynamicMemberAccessNode):
            target_str = self.to_source(node.target)
            return f"{target_str}.({self.to_source(node.member_expr)})"

        if isinstance(node, DynamicMethodCallNode):
            target_str = self.to_source(node.target)
            args_str = ", ".join(self.to_source(a) for a in node.arguments)
            return f"{target_str}.({self.to_source(node.method_expr)})({args_str})"

        if isinstance(node, DynamicStaticMemberAccessNode):
            clean_type = node.type_name.strip("[]")
            if node.arguments is not None:
                args_str = ", ".join(self.to_source(a) for a in node.arguments)
                return f"[{clean_type}]::({self.to_source(node.member_expr)})({args_str})"
            return f"[{clean_type}]::({self.to_source(node.member_expr)})"

        if isinstance(node, UnaryOpNode):
            return f"{node.operator} {self.to_source(node.operand)}"

        if isinstance(node, IndexAccessNode):
            target_str = self.to_source(node.target)
            if isinstance(node.index, ArrayLiteralNode):
                indices_str = ", ".join(self.to_source(e) for e in node.index.elements)
                return f"{target_str}[{indices_str}]"
            return f"{target_str}[{self.to_source(node.index)}]"

        if isinstance(node, IfStatementNode):
            cond_str = self.to_source(node.condition)
            then_str = self.to_source(node.then_branch)
            res = f"if ({cond_str}) {then_str}"
            if node.else_branch is not None:
                else_str = self.to_source(node.else_branch)
                res += f" else {else_str}"
            return res

        if isinstance(node, WhileStatementNode):
            cond_str = self.to_source(node.condition)
            body_str = self.to_source(node.body)
            return f"while ({cond_str}) {body_str}"

        return ""


