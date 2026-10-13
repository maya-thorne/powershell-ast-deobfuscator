"""
PowerShell Abstract Syntax Tree (AST) Visualizer & Tree Renderer.
Renders hierarchical syntax trees in Unicode/ASCII formats for forensic triage and analysis.
"""

from typing import Any, List, Optional, Tuple, Union

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
    SubexpressionNode,
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)
from .lexer import PowerShellLexer
from .parser import PowerShellParser


class ASTVisualizer:
    """
    Renders PowerShell AST nodes into clean hierarchical ASCII/Unicode trees.
    """

    def __init__(
        self,
        unicode: bool = True,
        show_types: bool = True,
        show_values: bool = True,
        max_depth: int = 100,
        truncate_len: int = 60,
        show_edge_labels: bool = True,
    ):
        self.unicode = unicode
        self.show_types = show_types
        self.show_values = show_values
        self.max_depth = max_depth
        self.truncate_len = truncate_len
        self.show_edge_labels = show_edge_labels

        if self.unicode:
            self.branch = "├── "
            self.last_branch = "└── "
            self.pipe = "│   "
            self.space = "    "
        else:
            self.branch = "|-- "
            self.last_branch = "\\-- "
            self.pipe = "|   "
            self.space = "    "

    def _truncate(self, text: str) -> str:
        text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
        if len(text) > self.truncate_len:
            return text[: self.truncate_len - 3] + "..."
        return text

    def get_node_label(self, node: ASTNode) -> str:
        """Generates a concise, informative label for an AST node."""
        if isinstance(node, ScriptBlockNode):
            status = "nested" if node.is_nested else "root"
            count = len(node.statements)
            return f"ScriptBlock ({status}, {count} statement{'s' if count != 1 else ''})"

        if isinstance(node, SubexpressionNode):
            count = len(node.statements)
            return f"Subexpression ($({count} statement{'s' if count != 1 else ''}))"

        if isinstance(node, PipelineNode):
            count = len(node.elements)
            return f"Pipeline ({count} stage{'s' if count != 1 else ''})"

        if isinstance(node, CommandNode):
            arg_count = len(node.arguments)
            return f"Command ({arg_count} arg{'s' if arg_count != 1 else ''})"

        if isinstance(node, StringLiteralNode):
            enc = "double-quoted" if node.is_expandable else "single-quoted"
            val = self._truncate(node.value)
            return f"StringLiteral: '{val}' ({enc})"

        if isinstance(node, NumberLiteralNode):
            return f"NumberLiteral: {node.raw} ({type(node.value).__name__})"

        if isinstance(node, VariableNode):
            scope_prefix = f"{node.scope}:" if node.scope else ""
            return f"Variable: ${scope_prefix}{node.name}"

        if isinstance(node, IdentifierNode):
            return f"Identifier: '{self._truncate(node.name)}'"

        if isinstance(node, BinaryOpNode):
            return f"BinaryOp: {node.operator}"

        if isinstance(node, UnaryOpNode):
            return f"UnaryOp: {node.operator}"

        if isinstance(node, FormatOpNode):
            count = len(node.arguments)
            return f"FormatOp: -f ({count} arg{'s' if count != 1 else ''})"

        if isinstance(node, AssignmentNode):
            scope_prefix = f"{node.variable.scope}:" if node.variable.scope else ""
            return f"Assignment: ${scope_prefix}{node.variable.name} ="

        if isinstance(node, ParenthesizedExpressionNode):
            return "ParenthesizedExpression"

        if isinstance(node, RangeExpressionNode):
            return "RangeExpression: .."

        if isinstance(node, ArrayLiteralNode):
            count = len(node.elements)
            return f"ArrayLiteral ({count} element{'s' if count != 1 else ''})"

        if isinstance(node, TypeCastNode):
            return f"TypeCast: [{node.type_name}]"

        if isinstance(node, MemberAccessNode):
            return f"MemberAccess: .{node.member}"

        if isinstance(node, StaticMemberAccessNode):
            if node.arguments is not None:
                arg_count = len(node.arguments)
                return f"StaticMemberCall: [{node.type_name}]::{node.member}({arg_count} args)"
            return f"StaticMemberAccess: [{node.type_name}]::{node.member}"

        if isinstance(node, MethodCallNode):
            arg_count = len(node.arguments)
            return f"MethodCall: .{node.method_name}({arg_count} args)"

        if isinstance(node, IndexAccessNode):
            return "IndexAccess: target[index]"

        if isinstance(node, DynamicMemberAccessNode):
            return "DynamicMemberAccess: target.(expr)"

        if isinstance(node, DynamicMethodCallNode):
            arg_count = len(node.arguments)
            return f"DynamicMethodCall: target.(expr)({arg_count} args)"

        if isinstance(node, DynamicStaticMemberAccessNode):
            if node.arguments is not None:
                arg_count = len(node.arguments)
                return f"DynamicStaticMemberCall: [{node.type_name}]::(expr)({arg_count} args)"
            return f"DynamicStaticMemberAccess: [{node.type_name}]::(expr)"

        if isinstance(node, IfStatementNode):
            has_else = "with else" if node.else_branch else "single branch"
            return f"IfStatement ({has_else})"

        if isinstance(node, WhileStatementNode):
            return "WhileStatement"

        return node.__class__.__name__

    def get_children(self, node: ASTNode) -> List[Tuple[str, ASTNode]]:
        """Returns ordered list of (edge_label, child_node) tuples."""
        children: List[Tuple[str, ASTNode]] = []

        if isinstance(node, ScriptBlockNode):
            for i, stmt in enumerate(node.statements):
                children.append((f"stmt[{i}]", stmt))

        elif isinstance(node, SubexpressionNode):
            for i, stmt in enumerate(node.statements):
                children.append((f"stmt[{i}]", stmt))

        elif isinstance(node, PipelineNode):
            for i, stage in enumerate(node.elements):
                children.append((f"stage[{i}]", stage))

        elif isinstance(node, CommandNode):
            children.append(("target", node.target))
            for i, arg in enumerate(node.arguments):
                children.append((f"arg[{i}]", arg))

        elif isinstance(node, BinaryOpNode):
            children.append(("left", node.left))
            children.append(("right", node.right))

        elif isinstance(node, FormatOpNode):
            children.append(("format", node.format_string))
            for i, arg in enumerate(node.arguments):
                children.append((f"arg[{i}]", arg))

        elif isinstance(node, AssignmentNode):
            children.append(("variable", node.variable))
            children.append(("expression", node.expression))

        elif isinstance(node, ParenthesizedExpressionNode):
            children.append(("expression", node.expression))

        elif isinstance(node, RangeExpressionNode):
            children.append(("start", node.start))
            children.append(("end", node.end))

        elif isinstance(node, ArrayLiteralNode):
            for i, elem in enumerate(node.elements):
                children.append((f"elem[{i}]", elem))

        elif isinstance(node, TypeCastNode):
            children.append(("expression", node.expression))

        elif isinstance(node, MemberAccessNode):
            children.append(("target", node.target))

        elif isinstance(node, StaticMemberAccessNode):
            if node.arguments is not None:
                for i, arg in enumerate(node.arguments):
                    children.append((f"arg[{i}]", arg))

        elif isinstance(node, MethodCallNode):
            children.append(("target", node.target))
            for i, arg in enumerate(node.arguments):
                children.append((f"arg[{i}]", arg))

        elif isinstance(node, UnaryOpNode):
            children.append(("operand", node.operand))

        elif isinstance(node, IndexAccessNode):
            children.append(("target", node.target))
            children.append(("index", node.index))

        elif isinstance(node, DynamicMemberAccessNode):
            children.append(("target", node.target))
            children.append(("member_expr", node.member_expr))

        elif isinstance(node, DynamicMethodCallNode):
            children.append(("target", node.target))
            children.append(("method_expr", node.method_expr))
            for i, arg in enumerate(node.arguments):
                children.append((f"arg[{i}]", arg))

        elif isinstance(node, DynamicStaticMemberAccessNode):
            children.append(("member_expr", node.member_expr))
            if node.arguments is not None:
                for i, arg in enumerate(node.arguments):
                    children.append((f"arg[{i}]", arg))

        elif isinstance(node, IfStatementNode):
            children.append(("condition", node.condition))
            children.append(("then", node.then_branch))
            if node.else_branch:
                children.append(("else", node.else_branch))

        elif isinstance(node, WhileStatementNode):
            children.append(("condition", node.condition))
            children.append(("body", node.body))

        return children

    def render(self, node: ASTNode) -> str:
        """Renders the AST node and its subtrees into a visual tree string."""
        lines: List[str] = []
        root_label = self.get_node_label(node)
        lines.append(root_label)
        self._render_children(node, "", lines, depth=0)
        return "\n".join(lines)

    def _render_children(
        self, node: ASTNode, prefix: str, lines: List[str], depth: int
    ) -> None:
        if depth >= self.max_depth:
            lines.append(f"{prefix}{self.last_branch}[Max depth {self.max_depth} reached]")
            return

        children = self.get_children(node)
        total = len(children)
        for i, (edge_label, child) in enumerate(children):
            is_last = i == total - 1
            branch_str = self.last_branch if is_last else self.branch
            next_prefix = prefix + (self.space if is_last else self.pipe)

            child_label = self.get_node_label(child)
            if self.show_edge_labels and edge_label:
                line_text = f"{prefix}{branch_str}[{edge_label}] {child_label}"
            else:
                line_text = f"{prefix}{branch_str}{child_label}"

            lines.append(line_text)
            self._render_children(child, next_prefix, lines, depth + 1)


def render_ast_tree(
    node_or_code: Union[ASTNode, str],
    unicode: bool = True,
    max_depth: int = 100,
    truncate_len: int = 60,
    show_edge_labels: bool = True,
) -> str:
    """
    Convenience function to parse (if necessary) and render an AST node or script string.
    """
    if isinstance(node_or_code, str):
        lexer = PowerShellLexer(node_or_code)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()
    else:
        ast = node_or_code

    visualizer = ASTVisualizer(
        unicode=unicode,
        max_depth=max_depth,
        truncate_len=truncate_len,
        show_edge_labels=show_edge_labels,
    )
    return visualizer.render(ast)
