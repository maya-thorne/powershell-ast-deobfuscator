"""
PowerShell AST Normalizer & Constant Folder.
Transforms obfuscated AST constructs into readable, simplified standard syntax.
"""

import re
from typing import Any, Dict, List, Optional

from .ast_nodes import (
    ASTNode,
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
    FormatOpNode,
    IdentifierNode,
    NumberLiteralNode,
    ParenthesizedExpressionNode,
    PipelineNode,
    ScriptBlockNode,
    StringLiteralNode,
    VariableNode,
)


class PowerShellNormalizer:
    """
    Traverses and normalizes PowerShell AST nodes.
    Folds string concatenations, formats '-f' templates, and strips backtick evasion artifacts.
    """

    def __init__(self, symbols: Optional[Dict[str, str]] = None):
        self.symbols = symbols or {}

    def normalize(self, node: ASTNode) -> ASTNode:
        return self.visit(node)

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
        return node

    def visit_script_block(self, node: ScriptBlockNode) -> ScriptBlockNode:
        norm_stmts = [self.visit(s) for s in node.statements]
        return ScriptBlockNode(statements=norm_stmts)

    def visit_pipeline(self, node: PipelineNode) -> ASTNode:
        norm_elements = [self.visit(e) for e in node.elements]
        if len(norm_elements) == 1:
            return norm_elements[0]
        return PipelineNode(elements=norm_elements)

    def visit_command(self, node: CommandNode) -> CommandNode:
        norm_target = self.visit(node.target)
        norm_args = [self.visit(a) for a in node.arguments]
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
            return f"${node.variable.name} = {self.to_source(node.expression)}"

        if isinstance(node, ParenthesizedExpressionNode):
            return f"({self.to_source(node.expression)})"

        return ""
