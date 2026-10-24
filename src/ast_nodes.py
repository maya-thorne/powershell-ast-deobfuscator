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
    is_nested: bool = False


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
    variable: ASTNode
    expression: ASTNode


@dataclass
class IdentifierNode(ASTNode):
    name: str


@dataclass
class ParenthesizedExpressionNode(ASTNode):
    expression: ASTNode


@dataclass
class RangeExpressionNode(ASTNode):
    """Represents PowerShell range expression: start..end (e.g., 1..16)."""
    start: ASTNode
    end: ASTNode


@dataclass
class ArrayLiteralNode(ASTNode):
    """Represents PowerShell array expression: @(item0, item1, ...) or (1, 2, ...)."""
    elements: List[ASTNode] = field(default_factory=list)


@dataclass
class TypeCastNode(ASTNode):
    """Represents PowerShell type cast: [type]expr (e.g., [byte[]](1..16))."""
    type_name: str
    expression: ASTNode


@dataclass
class MemberAccessNode(ASTNode):
    """Represents property or field access: target.member (e.g., $cred.Password)."""
    target: ASTNode
    member: str


@dataclass
class StaticMemberAccessNode(ASTNode):
    """Represents static type member access or constructor: [Type]::Member or [Type]::Method(args)."""
    type_name: str
    member: str
    arguments: Optional[List[ASTNode]] = None  # None if property/field access, list if method call


@dataclass
class MethodCallNode(ASTNode):
    """Represents instance method invocation: target.Method(arg0, arg1, ...)."""
    target: ASTNode
    method_name: str
    arguments: List[ASTNode] = field(default_factory=list)


@dataclass
class UnaryOpNode(ASTNode):
    """Represents unary operator invocation: -join expr, etc."""
    operator: str
    operand: ASTNode


@dataclass
class IndexAccessNode(ASTNode):
    """Represents array indexing or slicing: target[index] or target[i1, i2] or target[start..end]."""
    target: ASTNode
    index: ASTNode


@dataclass
class DynamicMemberAccessNode(ASTNode):
    """Represents dynamic property/member access: target.(member_expr) (e.g., $obj.('Length'))."""
    target: ASTNode
    member_expr: ASTNode


@dataclass
class DynamicMethodCallNode(ASTNode):
    """Represents dynamic method invocation: target.(method_expr)(args) (e.g., $obj.('Substring')(0, 5))."""
    target: ASTNode
    method_expr: ASTNode
    arguments: List[ASTNode] = field(default_factory=list)


@dataclass
class DynamicStaticMemberAccessNode(ASTNode):
    """Represents dynamic static member access: [Type]::(expr) or [Type]::(expr)(args)."""
    type_name: str
    member_expr: ASTNode
    arguments: Optional[List[ASTNode]] = None  # None if property, list if method call


@dataclass
class IfStatementNode(ASTNode):
    """Represents PowerShell conditional: if (condition) { then_branch } else { else_branch }."""
    condition: ASTNode
    then_branch: ASTNode
    else_branch: Optional[ASTNode] = None


@dataclass
class WhileStatementNode(ASTNode):
    """Represents PowerShell loop: while (condition) { body }."""
    condition: ASTNode
    body: ASTNode


@dataclass
class SubexpressionNode(ASTNode):
    """Represents PowerShell subexpression: $(statements)."""
    statements: List[ASTNode] = field(default_factory=list)

    def accept(self, visitor: Any) -> Any:
        return visitor.visit(self)


@dataclass
class ForStatementNode(ASTNode):
    """Represents PowerShell for loop: for (initializer; condition; iterator) { body }."""
    initializer: Optional[ASTNode] = None
    condition: Optional[ASTNode] = None
    iterator: Optional[ASTNode] = None
    body: Optional[ASTNode] = None


@dataclass
class ForEachStatementNode(ASTNode):
    """Represents PowerShell foreach loop: foreach ($variable in $collection) { body }."""
    variable: Optional[ASTNode] = None
    collection: Optional[ASTNode] = None
    body: Optional[ASTNode] = None


@dataclass
class CoalesceExpressionNode(ASTNode):
    """Represents PowerShell 7+ null-coalescing expression: left ?? right."""
    left: ASTNode
    right: ASTNode


@dataclass
class CoalesceAssignmentNode(ASTNode):
    """Represents PowerShell 7+ null-coalescing assignment: variable ??= expression."""
    variable: ASTNode
    expression: ASTNode


@dataclass
class TernaryExpressionNode(ASTNode):
    """Represents PowerShell 7+ ternary expression: condition ? if_true : if_false."""
    condition: ASTNode
    if_true: ASTNode
    if_false: ASTNode
