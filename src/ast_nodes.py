"""
PowerShell Abstract Syntax Tree (AST) node hierarchy.
"""

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class ASTNode:
    """Base class for all AST nodes."""
    def accept(self, visitor: Any) -> Any:
        return visitor.visit(self)


@dataclass
class ScriptBlockNode(ASTNode):
    statements: List[ASTNode] = field(default_factory=list)


@dataclass
class PipelineNode(ASTNode):
    elements: List[ASTNode] = field(default_factory=list)


@dataclass
class CommandNode(ASTNode):
    target: ASTNode
    arguments: List[ASTNode] = field(default_factory=list)


@dataclass
class StringLiteralNode(ASTNode):
    value: str
    is_expandable: bool = False  # False: single-quoted (''), True: double-quoted ("")


@dataclass
class NumberLiteralNode(ASTNode):
    value: Any  # int or float
    raw: str


@dataclass
class VariableNode(ASTNode):
    name: str
    scope: Optional[str] = None  # e.g., 'env', 'global', 'script'


@dataclass
class BinaryOpNode(ASTNode):
    left: ASTNode
    operator: str  # '+', '-', '*', '/'
    right: ASTNode


@dataclass
class FormatOpNode(ASTNode):
    """Represents PowerShell '-f' string format operator: 'format' -f arg0, arg1, ..."""
    format_string: ASTNode
    arguments: List[ASTNode] = field(default_factory=list)


@dataclass
class AssignmentNode(ASTNode):
    variable: VariableNode
    expression: ASTNode


@dataclass
class IdentifierNode(ASTNode):
    name: str


@dataclass
class ParenthesizedExpressionNode(ASTNode):
    expression: ASTNode
