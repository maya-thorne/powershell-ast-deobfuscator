"""
PowerShell 7+ (Core / pwsh) AST Reducer & Operator Folder.
Evaluates null-coalescing (??), null-coalescing assignment (??=),
and ternary (?:) expressions, eliminating dead branches and folding constants.
"""

import fnmatch
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union

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


class PowerShell7Reducer:
    """
    Compiler-grade AST reducer for PowerShell 7+ language extensions.
    Statically analyzes nullness and truthiness to fold ternary operators
    and null-coalescing chains, performing dead code elimination.
    """

    def __init__(
        self,
        symbols: Optional[Dict[str, Any]] = None,
        env: Optional[Dict[str, str]] = None,
    ):
        self.symbols: Dict[str, Any] = symbols if symbols is not None else {}
        self.env: Dict[str, str] = env if env is not None else dict(os.environ)

    def reduce(self, node: ASTNode) -> ASTNode:
        """Traverses the AST and reduces PowerShell 7+ expressions."""
        return self.visit(node)

    def evaluate_truthiness(self, node: ASTNode) -> Optional[bool]:
        """
        Statically evaluates whether an AST node is truthy or falsy according
        to PowerShell 7 type conversion and conditional evaluation rules.
        Returns True for truthy, False for falsy, or None if undecidable.
        """
        if isinstance(node, ParenthesizedExpressionNode):
            return self.evaluate_truthiness(node.expression)

        if isinstance(node, NumberLiteralNode):
            return node.value != 0

        if isinstance(node, StringLiteralNode):
            return len(node.value) > 0

        if isinstance(node, ArrayLiteralNode):
            return len(node.elements) > 0

        if isinstance(node, VariableNode):
            name_lower = node.name.lower()
            if name_lower in ("true", "1"):
                return True
            if name_lower in ("false", "0", "null"):
                return False
            if node.scope and node.scope.lower() == "env":
                env_val = self.env.get(node.name)
                if env_val is None or len(env_val) == 0:
                    return False
                return True
            if node.name in self.symbols:
                val = self.symbols[node.name]
                if val is None:
                    return False
                if isinstance(val, bool):
                    return val
                if isinstance(val, (int, float)):
                    return val != 0
                if isinstance(val, (str, list, tuple, dict, set)):
                    return len(val) > 0
                return True
            return None

        if isinstance(node, IdentifierNode):
            name_lower = node.name.lower()
            if name_lower in ("$true", "true"):
                return True
            if name_lower in ("$false", "false", "$null", "null"):
                return False
            if node.name.isdigit():
                return int(node.name) != 0
            return None

        if isinstance(node, UnaryOpNode):
            op = node.operator.lower()
            if op in ("!", "-not"):
                sub_truth = self.evaluate_truthiness(node.operand)
                if sub_truth is not None:
                    return not sub_truth
            elif op == "+":
                return self.evaluate_truthiness(node.operand)

        if isinstance(node, BinaryOpNode):
            return self._evaluate_binary_truthiness(node)

        if isinstance(node, TernaryExpressionNode):
            cond_truth = self.evaluate_truthiness(node.condition)
            if cond_truth is True:
                return self.evaluate_truthiness(node.if_true)
            if cond_truth is False:
                return self.evaluate_truthiness(node.if_false)

        if isinstance(node, CoalesceExpressionNode):
            left_null = self.evaluate_nullness(node.left)
            if left_null is True:
                return self.evaluate_truthiness(node.right)
            if left_null is False:
                return self.evaluate_truthiness(node.left)

        return None

    def _evaluate_binary_truthiness(self, node: BinaryOpNode) -> Optional[bool]:
        """Evaluates comparison and logical binary operators."""
        op = node.operator.lower()

        # Logical operators: -and, -or, -xor
        if op == "-and":
            l_truth = self.evaluate_truthiness(node.left)
            r_truth = self.evaluate_truthiness(node.right)
            if l_truth is False or r_truth is False:
                return False
            if l_truth is True and r_truth is True:
                return True
            return None

        if op == "-or":
            l_truth = self.evaluate_truthiness(node.left)
            r_truth = self.evaluate_truthiness(node.right)
            if l_truth is True or r_truth is True:
                return True
            if l_truth is False and r_truth is False:
                return False
            return None

        if op == "-xor":
            l_truth = self.evaluate_truthiness(node.left)
            r_truth = self.evaluate_truthiness(node.right)
            if l_truth is not None and r_truth is not None:
                return l_truth ^ r_truth
            return None

        # Comparison operators
        l_val = self._extract_constant_value(node.left)
        r_val = self._extract_constant_value(node.right)
        if l_val is None or r_val is None:
            return None

        try:
            if op == "-eq":
                if isinstance(l_val, str) and isinstance(r_val, str):
                    return l_val.lower() == r_val.lower()
                return l_val == r_val
            if op == "-ne":
                if isinstance(l_val, str) and isinstance(r_val, str):
                    return l_val.lower() != r_val.lower()
                return l_val != r_val
            if op == "-gt":
                return l_val > r_val
            if op == "-ge":
                return l_val >= r_val
            if op == "-lt":
                return l_val < r_val
            if op == "-le":
                return l_val <= r_val
            if op == "-like":
                pattern = str(r_val)
                target = str(l_val)
                return fnmatch.fnmatchcase(target.lower(), pattern.lower())
            if op == "-notlike":
                pattern = str(r_val)
                target = str(l_val)
                return not fnmatch.fnmatchcase(target.lower(), pattern.lower())
            if op == "-match":
                return bool(re.search(str(r_val), str(l_val), re.IGNORECASE))
            if op == "-notmatch":
                return not bool(re.search(str(r_val), str(l_val), re.IGNORECASE))
        except Exception:
            return None

        return None

    def evaluate_nullness(self, node: ASTNode) -> Optional[bool]:
        """
        Determines if an AST node statically evaluates to $null (True)
        or definitely non-null (False). Returns None if indeterminate.
        """
        if isinstance(node, ParenthesizedExpressionNode):
            return self.evaluate_nullness(node.expression)

        if isinstance(node, (StringLiteralNode, NumberLiteralNode, ArrayLiteralNode, FormatOpNode, RangeExpressionNode)):
            return False

        if isinstance(node, VariableNode):
            name_lower = node.name.lower()
            if name_lower == "null":
                return True
            if name_lower in ("true", "false"):
                return False
            if node.name in self.symbols:
                return self.symbols[node.name] is None
            return None

        if isinstance(node, IdentifierNode):
            name_lower = node.name.lower()
            if name_lower in ("$null", "null"):
                return True
            if name_lower in ("$true", "true", "$false", "false"):
                return False
            return None

        if isinstance(node, TypeCastNode):
            # Type casts [type]expr generally instantiate non-null objects
            sub_null = self.evaluate_nullness(node.expression)
            if sub_null is False:
                return False
            return None

        if isinstance(node, UnaryOpNode):
            return False

        if isinstance(node, BinaryOpNode):
            return False

        if isinstance(node, CoalesceExpressionNode):
            left_null = self.evaluate_nullness(node.left)
            if left_null is False:
                return False
            if left_null is True:
                return self.evaluate_nullness(node.right)
            return None

        if isinstance(node, TernaryExpressionNode):
            cond_truth = self.evaluate_truthiness(node.condition)
            if cond_truth is True:
                return self.evaluate_nullness(node.if_true)
            if cond_truth is False:
                return self.evaluate_nullness(node.if_false)
            return None

        return None

    def _extract_constant_value(self, node: ASTNode) -> Any:
        """Extracts native Python primitive value from constant AST nodes."""
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_constant_value(node.expression)
        if isinstance(node, StringLiteralNode):
            return node.value
        if isinstance(node, NumberLiteralNode):
            return node.value
        if isinstance(node, VariableNode):
            name_lower = node.name.lower()
            if name_lower == "true":
                return True
            if name_lower == "false":
                return False
            if name_lower == "null":
                return None
            if node.name in self.symbols:
                return self.symbols[node.name]
            return None
        if isinstance(node, IdentifierNode):
            name_lower = node.name.lower()
            if name_lower in ("$true", "true"):
                return True
            if name_lower in ("$false", "false"):
                return False
            if name_lower in ("$null", "null"):
                return None
            if node.name.isdigit():
                return int(node.name)
            return None
        if isinstance(node, ArrayLiteralNode):
            elems = [self._extract_constant_value(e) for e in node.elements]
            if all(e is not None for e in elems):
                return elems
            return None
        return None

    def visit(self, node: ASTNode) -> ASTNode:
        """Recursive AST node visitor with PowerShell 7+ optimizations."""
        if isinstance(node, ScriptBlockNode):
            return ScriptBlockNode(
                statements=[self.visit(s) for s in node.statements],
                is_nested=node.is_nested,
            )
        if isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self.visit(s) for s in node.statements])
        if isinstance(node, PipelineNode):
            elements = [self.visit(e) for e in node.elements]
            if len(elements) == 1:
                return elements[0]
            return PipelineNode(elements=elements)
        if isinstance(node, CommandNode):
            return CommandNode(
                target=self.visit(node.target),
                arguments=[self.visit(a) for a in node.arguments],
            )
        if isinstance(node, ParenthesizedExpressionNode):
            inner = self.visit(node.expression)
            if isinstance(inner, (StringLiteralNode, NumberLiteralNode, IdentifierNode, VariableNode)):
                return inner
            return ParenthesizedExpressionNode(expression=inner)
        if isinstance(node, BinaryOpNode):
            return BinaryOpNode(
                left=self.visit(node.left),
                operator=node.operator,
                right=self.visit(node.right),
            )
        if isinstance(node, UnaryOpNode):
            return UnaryOpNode(operator=node.operator, operand=self.visit(node.operand))
        if isinstance(node, FormatOpNode):
            return FormatOpNode(
                format_string=self.visit(node.format_string),
                arguments=[self.visit(a) for a in node.arguments],
            )
        if isinstance(node, AssignmentNode):
            norm_var = self.visit(node.variable)
            norm_expr = self.visit(node.expression)
            if isinstance(norm_var, VariableNode):
                const_val = self._extract_constant_value(norm_expr)
                if const_val is not None:
                    self.symbols[norm_var.name] = const_val
            return AssignmentNode(variable=norm_var, expression=norm_expr)
        if isinstance(node, CoalesceAssignmentNode):
            return self.visit_coalesce_assignment(node)
        if isinstance(node, CoalesceExpressionNode):
            return self.visit_coalesce_expression(node)
        if isinstance(node, TernaryExpressionNode):
            return self.visit_ternary_expression(node)
        if isinstance(node, IfStatementNode):
            return IfStatementNode(
                condition=self.visit(node.condition),
                then_branch=self.visit(node.then_branch),
                else_branch=self.visit(node.else_branch) if node.else_branch else None,
            )
        if isinstance(node, WhileStatementNode):
            return WhileStatementNode(condition=self.visit(node.condition), body=self.visit(node.body))
        if isinstance(node, ForStatementNode):
            return ForStatementNode(
                initializer=self.visit(node.initializer) if node.initializer else None,
                condition=self.visit(node.condition) if node.condition else None,
                iterator=self.visit(node.iterator) if node.iterator else None,
                body=self.visit(node.body) if node.body else None,
            )
        if isinstance(node, ForEachStatementNode):
            return ForEachStatementNode(
                variable=self.visit(node.variable) if node.variable else None,
                collection=self.visit(node.collection) if node.collection else None,
                body=self.visit(node.body) if node.body else None,
            )
        if isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        if isinstance(node, RangeExpressionNode):
            return RangeExpressionNode(start=self.visit(node.start), end=self.visit(node.end))
        if isinstance(node, TypeCastNode):
            return TypeCastNode(type_name=node.type_name, expression=self.visit(node.expression))
        if isinstance(node, MemberAccessNode):
            return MemberAccessNode(target=self.visit(node.target), member=node.member)
        if isinstance(node, StaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)
        if isinstance(node, MethodCallNode):
            return MethodCallNode(
                target=self.visit(node.target),
                method_name=node.method_name,
                arguments=[self.visit(a) for a in node.arguments],
            )
        if isinstance(node, DynamicMemberAccessNode):
            return DynamicMemberAccessNode(target=self.visit(node.target), member_expr=self.visit(node.member_expr))
        if isinstance(node, DynamicMethodCallNode):
            return DynamicMethodCallNode(
                target=self.visit(node.target),
                method_expr=self.visit(node.method_expr),
                arguments=[self.visit(a) for a in node.arguments],
            )
        if isinstance(node, DynamicStaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return DynamicStaticMemberAccessNode(
                type_name=node.type_name,
                member_expr=self.visit(node.member_expr),
                arguments=norm_args,
            )
        if isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self.visit(node.target), index=self.visit(node.index))

        return node

    def visit_coalesce_assignment(self, node: CoalesceAssignmentNode) -> ASTNode:
        """
        Reduces null-coalescing assignment: $var ??= expr
        If $var is already bound to a non-null value, this assignment is a no-op ($var).
        If $var is null or unbound, evaluates and assigns expr.
        """
        norm_var = self.visit(node.variable)
        norm_expr = self.visit(node.expression)

        if isinstance(norm_var, VariableNode) and norm_var.name in self.symbols:
            current_val = self.symbols[norm_var.name]
            if current_val is not None:
                # Variable already has non-null value; ??= assignment is redundant
                return norm_var

        if isinstance(norm_var, VariableNode):
            expr_val = self._extract_constant_value(norm_expr)
            if expr_val is not None:
                self.symbols[norm_var.name] = expr_val

        return CoalesceAssignmentNode(variable=norm_var, expression=norm_expr)

    def visit_coalesce_expression(self, node: CoalesceExpressionNode) -> ASTNode:
        """
        Folds null-coalescing expression: left ?? right
        - If left is statically known to be $null -> right
        - If left is statically known to be non-null -> left
        - Otherwise returns reduced CoalesceExpressionNode.
        """
        norm_left = self.visit(node.left)
        norm_right = self.visit(node.right)

        left_null = self.evaluate_nullness(norm_left)
        if left_null is True:
            return norm_right
        if left_null is False:
            return norm_left

        return CoalesceExpressionNode(left=norm_left, right=norm_right)

    def visit_ternary_expression(self, node: TernaryExpressionNode) -> ASTNode:
        """
        Folds ternary expression: condition ? if_true : if_false
        - If condition evaluates to True -> if_true (dead code eliminates if_false)
        - If condition evaluates to False -> if_false (dead code eliminates if_true)
        - Otherwise returns reduced TernaryExpressionNode.
        """
        norm_cond = self.visit(node.condition)
        norm_true = self.visit(node.if_true)
        norm_false = self.visit(node.if_false)

        truth = self.evaluate_truthiness(norm_cond)
        if truth is True:
            return norm_true
        if truth is False:
            return norm_false

        return TernaryExpressionNode(condition=norm_cond, if_true=norm_true, if_false=norm_false)
