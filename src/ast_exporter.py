"""
PowerShell Abstract Syntax Tree (AST) Exporter & Graph Generator.
Exports AST hierarchies to Mermaid diagrams, Graphviz DOT graphs, structured JSON, and metrics.
"""

import json
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .ast_nodes import (
    ASTNode,
    ArrayLiteralNode,
    AssignmentNode,
    BinaryOpNode,
    CoalesceAssignmentNode,
    CoalesceExpressionNode,
    CommandNode,
    DynamicMemberAccessNode,
    DynamicMethodCallNode,
    DynamicStaticMemberAccessNode,
    ForEachStatementNode,
    FormatOpNode,
    ForStatementNode,
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
    TernaryExpressionNode,
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)
from .ast_visualizer import ASTVisualizer
from .lexer import PowerShellLexer
from .parser import PowerShellParser


class ASTExporter:
    """
    Exports PowerShell AST nodes into diagrams (Mermaid, DOT), JSON documents, and metrics.
    """

    def __init__(self, max_depth: int = 100, truncate_len: int = 50):
        self.max_depth = max_depth
        self.truncate_len = truncate_len
        self.visualizer = ASTVisualizer(max_depth=max_depth, truncate_len=truncate_len)

    def _escape_mermaid(self, text: str) -> str:
        """Escapes special characters to ensure valid, safe Mermaid node labels."""
        text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        if len(text) > self.truncate_len:
            text = text[: self.truncate_len - 3] + "..."
        # Replace problematic characters for Mermaid syntax inside ["..."]
        text = (
            text.replace("&", "&amp;")
            .replace('"', "#quot;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("[", "&#91;")
            .replace("]", "&#93;")
            .replace("(", "&#40;")
            .replace(")", "&#41;")
            .replace("{", "&#123;")
            .replace("}", "&#125;")
        )
        return text

    def _escape_dot(self, text: str) -> str:
        """Escapes characters for Graphviz DOT label strings."""
        text = text.replace("\r", " ").replace("\n", "\\n").replace("\t", " ")
        if len(text) > self.truncate_len:
            text = text[: self.truncate_len - 3] + "..."
        text = text.replace("\\", "\\\\").replace('"', '\\"')
        return text

    def _get_mermaid_shape(self, node: ASTNode, node_id: str, label: str) -> str:
        """Assigns semantic shapes in Mermaid based on AST node category."""
        escaped = self._escape_mermaid(label)
        if isinstance(node, (IfStatementNode, WhileStatementNode, ForStatementNode, ForEachStatementNode, TernaryExpressionNode)):
            return f'{node_id}{{"{escaped}"}}'  # Diamond for control flow
        if isinstance(node, (ScriptBlockNode, SubexpressionNode)):
            return f'{node_id}[["{escaped}"]]'  # Subroutine for scriptblocks and subexpressions
        if isinstance(node, (StringLiteralNode, NumberLiteralNode, VariableNode, IdentifierNode)):
            return f'{node_id}(["{escaped}"])'  # Stadium for literals/variables
        if isinstance(node, (BinaryOpNode, UnaryOpNode, FormatOpNode, CoalesceExpressionNode, CoalesceAssignmentNode)):
            return f'{node_id}("{escaped}")'  # Rounded for operators
        if isinstance(node, (TypeCastNode, StaticMemberAccessNode, MethodCallNode, MemberAccessNode)):
            return f'{node_id}[/"{escaped}"\\]'  # Trapezoid for types and members
        return f'{node_id}["{escaped}"]'  # Default rectangle

    def _get_dot_style(self, node: ASTNode) -> Tuple[str, str, str]:
        """Returns (shape, fillcolor, color) for Graphviz DOT nodes."""
        if isinstance(node, (ScriptBlockNode, SubexpressionNode)):
            return "box", "#e0f2fe", "#0284c7"
        if isinstance(node, (IfStatementNode, WhileStatementNode, ForStatementNode, ForEachStatementNode, TernaryExpressionNode)):
            return "diamond", "#fee2e2", "#ef4444"
        if isinstance(node, (StringLiteralNode, NumberLiteralNode, VariableNode, IdentifierNode)):
            return "ellipse", "#dcfce7", "#22c55e"
        if isinstance(node, (BinaryOpNode, UnaryOpNode, FormatOpNode, CoalesceExpressionNode, CoalesceAssignmentNode)):
            return "parallelogram", "#f3e8ff", "#a855f7"
        if isinstance(node, (CommandNode, PipelineNode)):
            return "box", "#fef3c7", "#f59e0b"
        return "box", "#f1f5f9", "#64748b"

    def to_mermaid(
        self, node: ASTNode, direction: str = "TD", wrap_markdown: bool = False
    ) -> str:
        """Generates a Mermaid flowchart representation of the AST."""
        lines: List[str] = [f"flowchart {direction}"]
        node_counter = 0
        node_map: Dict[int, str] = {}

        def walk(current: ASTNode, depth: int) -> str:
            nonlocal node_counter
            current_id = f"node_{node_counter}"
            node_counter += 1
            node_map[id(current)] = current_id

            label = self.visualizer.get_node_label(current)
            shape_def = self._get_mermaid_shape(current, current_id, label)
            lines.append(f"    {shape_def}")

            if depth >= self.max_depth:
                return current_id

            children = self.visualizer.get_children(current)
            for edge_label, child in children:
                child_id = walk(child, depth + 1)
                safe_edge = self._escape_mermaid(edge_label) if edge_label else ""
                if safe_edge:
                    lines.append(f"    {current_id} -->|{safe_edge}| {child_id}")
                else:
                    lines.append(f"    {current_id} --> {child_id}")

            return current_id

        walk(node, depth=0)
        mermaid_code = "\n".join(lines)
        if wrap_markdown:
            return f"```mermaid\n{mermaid_code}\n```"
        return mermaid_code

    def to_dot(self, node: ASTNode, graph_name: str = "PowerShellAST") -> str:
        """Generates a Graphviz DOT representation of the AST."""
        lines: List[str] = [
            f"digraph {graph_name} {{",
            '  rankdir="TB";',
            '  node [fontname="Helvetica", fontsize=10, style="filled,rounded"];',
            '  edge [fontname="Helvetica", fontsize=9];',
        ]
        node_counter = 0

        def walk(current: ASTNode, depth: int) -> str:
            nonlocal node_counter
            current_id = f"node_{node_counter}"
            node_counter += 1

            label = self.visualizer.get_node_label(current)
            escaped_label = self._escape_dot(label)
            shape, fillcolor, color = self._get_dot_style(current)
            lines.append(
                f'  {current_id} [label="{escaped_label}", shape={shape}, fillcolor="{fillcolor}", color="{color}"];'
            )

            if depth >= self.max_depth:
                return current_id

            children = self.visualizer.get_children(current)
            for edge_label, child in children:
                child_id = walk(child, depth + 1)
                safe_edge = self._escape_dot(edge_label) if edge_label else ""
                if safe_edge:
                    lines.append(f'  {current_id} -> {child_id} [label="{safe_edge}"];')
                else:
                    lines.append(f"  {current_id} -> {child_id};")

            return current_id

        walk(node, depth=0)
        lines.append("}")
        return "\n".join(lines)

    def to_dict(self, node: ASTNode) -> Dict[str, Any]:
        """Converts an AST node hierarchy into a clean dictionary representation."""

        def convert(current: ASTNode, depth: int) -> Dict[str, Any]:
            if depth >= self.max_depth:
                return {"type": current.__class__.__name__, "truncated": True}

            node_data: Dict[str, Any] = {
                "type": current.__class__.__name__,
            }

            # Extract primitive properties
            attrs: Dict[str, Any] = {}
            for k, v in current.__dict__.items():
                if isinstance(v, (str, int, float, bool)) or v is None:
                    attrs[k] = v
            if attrs:
                node_data["attributes"] = attrs

            # Extract children with roles
            children_list: List[Dict[str, Any]] = []
            for role, child in self.visualizer.get_children(current):
                children_list.append({
                    "role": role,
                    "node": convert(child, depth + 1),
                })

            if children_list:
                node_data["children"] = children_list

            return node_data

        return convert(node, depth=0)

    def to_json(self, node: ASTNode, indent: int = 2) -> str:
        """Converts the AST hierarchy into a formatted JSON string."""
        return json.dumps(self.to_dict(node), indent=indent, ensure_ascii=False)

    def extract_metrics(self, node: ASTNode) -> Dict[str, Any]:
        """
        Computes structural metrics, node frequency, and complexity statistics.
        """
        type_counts: Dict[str, int] = {}
        total_nodes = 0
        max_depth = 0
        statement_count = 0
        pipeline_count = 0
        command_count = 0
        variable_count = 0
        literal_count = 0
        conditional_count = 0

        def traverse(current: ASTNode, depth: int) -> None:
            nonlocal total_nodes, max_depth, statement_count, pipeline_count
            nonlocal command_count, variable_count, literal_count, conditional_count

            total_nodes += 1
            if depth > max_depth:
                max_depth = depth

            name = current.__class__.__name__
            type_counts[name] = type_counts.get(name, 0) + 1

            if isinstance(current, (ScriptBlockNode, SubexpressionNode)):
                statement_count += len(current.statements)
            elif isinstance(current, PipelineNode):
                pipeline_count += 1
            elif isinstance(current, CommandNode):
                command_count += 1
            elif isinstance(current, VariableNode):
                variable_count += 1
            elif isinstance(current, (StringLiteralNode, NumberLiteralNode)):
                literal_count += 1
            elif isinstance(current, (IfStatementNode, WhileStatementNode, ForStatementNode, ForEachStatementNode)):
                conditional_count += 1

            if depth < self.max_depth:
                for _, child in self.visualizer.get_children(current):
                    traverse(child, depth + 1)

        traverse(node, depth=0)

        # Approximate cyclomatic complexity = 1 + branches/loops + (pipelines - 1 if pipelines else 0)
        cyclomatic = 1 + conditional_count + max(0, pipeline_count - 1)

        return {
            "total_nodes": total_nodes,
            "max_depth": max_depth,
            "statement_count": statement_count,
            "pipeline_count": pipeline_count,
            "command_count": command_count,
            "variable_count": variable_count,
            "literal_count": literal_count,
            "conditional_count": conditional_count,
            "cyclomatic_complexity": cyclomatic,
            "node_type_counts": dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True)),
        }


def export_ast_mermaid(
    node_or_code: Union[ASTNode, str],
    direction: str = "TD",
    wrap_markdown: bool = False,
    max_depth: int = 100,
) -> str:
    """Convenience helper to export an AST to Mermaid format."""
    if isinstance(node_or_code, str):
        lexer = PowerShellLexer(node_or_code)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()
    else:
        ast = node_or_code
    exporter = ASTExporter(max_depth=max_depth)
    return exporter.to_mermaid(ast, direction=direction, wrap_markdown=wrap_markdown)


def export_ast_dot(
    node_or_code: Union[ASTNode, str],
    graph_name: str = "PowerShellAST",
    max_depth: int = 100,
) -> str:
    """Convenience helper to export an AST to Graphviz DOT format."""
    if isinstance(node_or_code, str):
        lexer = PowerShellLexer(node_or_code)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()
    else:
        ast = node_or_code
    exporter = ASTExporter(max_depth=max_depth)
    return exporter.to_dot(ast, graph_name=graph_name)


def export_ast_json(
    node_or_code: Union[ASTNode, str],
    indent: int = 2,
    max_depth: int = 100,
) -> str:
    """Convenience helper to export an AST to JSON format."""
    if isinstance(node_or_code, str):
        lexer = PowerShellLexer(node_or_code)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()
    else:
        ast = node_or_code
    exporter = ASTExporter(max_depth=max_depth)
    return exporter.to_json(ast, indent=indent)


def extract_ast_metrics(
    node_or_code: Union[ASTNode, str],
    max_depth: int = 100,
) -> Dict[str, Any]:
    """Convenience helper to extract structural AST metrics and statistics."""
    if isinstance(node_or_code, str):
        lexer = PowerShellLexer(node_or_code)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()
    else:
        ast = node_or_code
    exporter = ASTExporter(max_depth=max_depth)
    return exporter.extract_metrics(ast)
