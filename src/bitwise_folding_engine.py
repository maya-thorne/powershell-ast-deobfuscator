"""
PowerShell Arithmetic and Bitwise Operator Static Folding Engine.
Evaluates binary and unary arithmetic, bitwise (-bxor, -band, -bor, -bnot, -shl, -shr),
and comparison operators on numeric literals and symbol-tracked constants.
"""

from typing import Any, Dict, Optional, Tuple, Union

from .ast_nodes import (
    ASTNode,
    ArrayLiteralNode,
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
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
from .type_accelerators import TypeAcceleratorRegistry


class PowerShellBitwiseFoldingEngine:
    """
    Compiler-grade AST transformer for constant folding of arithmetic and bitwise expressions.
    Evaluates:
      - Bitwise binary: -bxor, -band, -bor, -shl, -shr
      - Arithmetic binary: +, -, *, /, %
      - Unary: -bnot, -not, !, -, +
      - Comparisons: -eq, -ne, -gt, -ge, -lt, -le
      - Type casts over folded expressions: [char](0x41 -bxor 0x20) -> 'a'
    """

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols: Dict[str, Any] = symbols if symbols is not None else {}

    def fold(self, node: ASTNode) -> ASTNode:
        """Traverses the AST and recursively folds constant arithmetic and bitwise expressions."""
        return self._visit(node)

    def _visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            return ScriptBlockNode(
                statements=[self._visit(s) for s in node.statements],
                is_nested=node.is_nested,
            )

        if isinstance(node, PipelineNode):
            folded_elements = [self._visit(e) for e in node.elements]
            if len(folded_elements) == 1:
                return folded_elements[0]
            return PipelineNode(elements=folded_elements)

        if isinstance(node, CommandNode):
            return CommandNode(
                target=self._visit(node.target),
                arguments=[self._visit(a) for a in node.arguments],
            )

        if isinstance(node, BinaryOpNode):
            return self._visit_binary_op(node)

        if isinstance(node, UnaryOpNode):
            return self._visit_unary_op(node)

        if isinstance(node, TypeCastNode):
            return self._visit_type_cast(node)

        if isinstance(node, ParenthesizedExpressionNode):
            inner = self._visit(node.expression)
            if isinstance(inner, (NumberLiteralNode, StringLiteralNode, IdentifierNode)):
                return inner
            return ParenthesizedExpressionNode(expression=inner)

        if isinstance(node, AssignmentNode):
            # Do NOT substitute constant values into the assigned variable (LHS)
            norm_var: ASTNode
            if isinstance(node.variable, IndexAccessNode):
                norm_var = IndexAccessNode(
                    target=node.variable.target,
                    index=self._visit(node.variable.index),
                )
            else:
                norm_var = node.variable

            norm_expr = self._visit(node.expression)
            if isinstance(norm_var, VariableNode):
                if isinstance(norm_expr, NumberLiteralNode):
                    self.symbols[norm_var.name.lower()] = norm_expr.value
                elif isinstance(norm_expr, StringLiteralNode):
                    self.symbols[norm_var.name.lower()] = norm_expr.value
            return AssignmentNode(variable=norm_var, expression=norm_expr)

        if isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self._visit(e) for e in node.elements])

        if isinstance(node, RangeExpressionNode):
            return RangeExpressionNode(start=self._visit(node.start), end=self._visit(node.end))

        if isinstance(node, FormatOpNode):
            return FormatOpNode(
                format_string=self._visit(node.format_string),
                arguments=[self._visit(a) for a in node.arguments],
            )

        if isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self._visit(node.target), index=self._visit(node.index))

        if isinstance(node, MemberAccessNode):
            return MemberAccessNode(target=self._visit(node.target), member=node.member)

        if isinstance(node, StaticMemberAccessNode):
            norm_args = [self._visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)

        if isinstance(node, MethodCallNode):
            return MethodCallNode(
                target=self._visit(node.target),
                method_name=node.method_name,
                arguments=[self._visit(a) for a in node.arguments],
            )

        if isinstance(node, IfStatementNode):
            return IfStatementNode(
                condition=self._visit(node.condition),
                then_branch=self._visit(node.then_branch),
                else_branch=self._visit(node.else_branch) if node.else_branch else None,
            )

        if isinstance(node, WhileStatementNode):
            return WhileStatementNode(condition=self._visit(node.condition), body=self._visit(node.body))

        if isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self._visit(s) for s in node.statements])

        # Symbol resolution for numeric constants
        if isinstance(node, VariableNode):
            var_name = node.name.lower()
            if var_name in self.symbols and isinstance(self.symbols[var_name], (int, float)):
                val = self.symbols[var_name]
                return NumberLiteralNode(value=val, raw=str(val))

        return node

    def _visit_binary_op(self, node: BinaryOpNode) -> ASTNode:
        left = self._visit(node.left)
        right = self._visit(node.right)
        op = node.operator.lower()

        # String concatenation folding: 'a' + 'b' -> 'ab'
        if op == "+":
            if isinstance(left, StringLiteralNode) and isinstance(right, StringLiteralNode):
                return StringLiteralNode(
                    value=left.value + right.value,
                    is_expandable=left.is_expandable or right.is_expandable,
                )
            if isinstance(left, StringLiteralNode) and isinstance(right, NumberLiteralNode):
                return StringLiteralNode(
                    value=left.value + str(right.value),
                    is_expandable=left.is_expandable,
                )
            if isinstance(left, NumberLiteralNode) and isinstance(right, StringLiteralNode):
                return StringLiteralNode(
                    value=str(left.value) + right.value,
                    is_expandable=right.is_expandable,
                )

        # Numeric constant folding
        l_num = self._extract_numeric_value(left)
        r_num = self._extract_numeric_value(right)

        if l_num is not None and r_num is not None:
            folded_val = self._compute_binary(l_num, op, r_num)
            if folded_val is not None:
                if isinstance(folded_val, bool):
                    var_name = "true" if folded_val else "false"
                    return VariableNode(name=var_name)
                elif isinstance(folded_val, int):
                    return NumberLiteralNode(value=folded_val, raw=str(folded_val))
                elif isinstance(folded_val, float):
                    return NumberLiteralNode(value=folded_val, raw=str(folded_val))

        return BinaryOpNode(left=left, operator=node.operator, right=right)

    def _visit_unary_op(self, node: UnaryOpNode) -> ASTNode:
        operand = self._visit(node.operand)
        op = node.operator.lower()

        # Bitwise NOT: -bnot
        if op == "-bnot":
            num = self._extract_numeric_value(operand)
            if num is not None and isinstance(num, int):
                # Signed bitwise NOT
                res = ~num
                return NumberLiteralNode(value=res, raw=str(res))

        # Unary negation: -
        if op == "-":
            num = self._extract_numeric_value(operand)
            if num is not None:
                res = -num
                return NumberLiteralNode(value=res, raw=str(res))

        # Unary plus: +
        if op == "+":
            num = self._extract_numeric_value(operand)
            if num is not None:
                return NumberLiteralNode(value=num, raw=str(num))

        # Logical NOT: -not, !
        if op in ("-not", "!"):
            if isinstance(operand, VariableNode):
                if operand.name.lower() == "true":
                    return VariableNode(name="false")
                elif operand.name.lower() in ("false", "null"):
                    return VariableNode(name="true")
            elif isinstance(operand, NumberLiteralNode):
                is_true = operand.value != 0
                return VariableNode(name="false" if is_true else "true")
            elif isinstance(operand, StringLiteralNode):
                is_true = len(operand.value) > 0
                return VariableNode(name="false" if is_true else "true")

        return UnaryOpNode(operator=node.operator, operand=operand)

    def _visit_type_cast(self, node: TypeCastNode) -> ASTNode:
        expr = self._visit(node.expression)
        alias = TypeAcceleratorRegistry.get_canonical_alias(node.type_name).lower()

        # Cast folded numeric expression to char: [char](0x41 -bxor 0x20) -> 'a'
        if alias == "char":
            num = self._extract_numeric_value(expr)
            if num is not None:
                try:
                    int_val = int(num)
                    if 0 <= int_val <= 0x10FFFF:
                        return StringLiteralNode(value=chr(int_val), is_expandable=False)
                except (ValueError, OverflowError):
                    pass
            elif isinstance(expr, StringLiteralNode) and len(expr.value) == 1:
                return expr

        # Cast to integer types: [int], [byte], [long]
        if alias in ("int", "int32", "int64", "long", "byte"):
            num = self._extract_numeric_value(expr)
            if num is not None:
                try:
                    int_val = int(num)
                    if alias == "byte":
                        int_val = int_val & 0xFF
                    return NumberLiteralNode(value=int_val, raw=str(int_val))
                except (ValueError, OverflowError):
                    pass

        return TypeCastNode(type_name=node.type_name, expression=expr)

    def _extract_numeric_value(self, node: ASTNode) -> Optional[Union[int, float]]:
        """Extracts numeric integer or float value from a node or symbol table."""
        if isinstance(node, NumberLiteralNode):
            return node.value
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_numeric_value(node.expression)
        if isinstance(node, VariableNode):
            name = node.name.lower()
            if name in self.symbols and isinstance(self.symbols[name], (int, float)):
                return self.symbols[name]
        return None

    def _compute_binary(
        self, left: Union[int, float], op: str, right: Union[int, float]
    ) -> Optional[Union[int, float, bool]]:
        """Computes the binary operation with bounds and division safety guards."""
        try:
            # Bitwise operators (require integer operands)
            if op in ("-bxor", "^"):
                return int(left) ^ int(right)
            elif op in ("-band", "&"):
                return int(left) & int(right)
            elif op in ("-bor", "|"):
                return int(left) | int(right)
            elif op in ("-shl", "<<"):
                shift = int(right)
                if 0 <= shift <= 64:
                    return int(left) << shift
                return None
            elif op in ("-shr", ">>"):
                shift = int(right)
                if 0 <= shift <= 64:
                    return int(left) >> shift
                return None

            # Arithmetic operators
            elif op == "+":
                return left + right
            elif op == "-":
                return left - right
            elif op == "*":
                return left * right
            elif op == "/":
                if right == 0:
                    return None  # Guard against division by zero
                # If integer division without remainder, return int
                if isinstance(left, int) and isinstance(right, int) and left % right == 0:
                    return left // right
                return left / right
            elif op == "%":
                if right == 0:
                    return None  # Guard against modulo by zero
                return left % right

            # Comparison operators
            elif op == "-eq":
                return left == right
            elif op == "-ne":
                return left != right
            elif op == "-gt":
                return left > right
            elif op == "-ge":
                return left >= right
            elif op == "-lt":
                return left < right
            elif op == "-le":
                return left <= right

        except (ValueError, OverflowError, ZeroDivisionError):
            return None

        return None
