"""
PowerShell AST ScriptBlock & Control Flow Simplifier.
Simplifies ScriptBlock invocations (& { ... }, . { ... }, { ... }.Invoke()),
folds trivial conditionals (if ($true), if ($false)), and eliminates dead code.
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


class PowerShellScriptBlockSimplifier:
    """
    Control flow and ScriptBlock reducer for PowerShell AST.
    Inlines invocation wrappers (& { ... }, . { ... }, { ... }.Invoke()),
    eliminates unreachable decoy branches, and evaluates static condition trees.
    """

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols = symbols if symbols is not None else {}

    def simplify(self, node: ASTNode) -> ASTNode:
        """Entry point for control flow and ScriptBlock simplification."""
        return self.visit(node)

    def visit(self, node: Optional[ASTNode]) -> Optional[ASTNode]:
        if node is None:
            return None

        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        elif isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self.visit(s) for s in node.statements])
        elif isinstance(node, IfStatementNode):
            return self.visit_if_statement(node)
        elif isinstance(node, WhileStatementNode):
            return self.visit_while_statement(node)
        elif isinstance(node, CommandNode):
            return self.visit_command(node)
        elif isinstance(node, MethodCallNode):
            return self.visit_method_call(node)
        elif isinstance(node, AssignmentNode):
            return self.visit_assignment(node)
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, ParenthesizedExpressionNode):
            return self.visit_parenthesized(node)
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
        elif isinstance(node, StaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)
        elif isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self.visit(node.target), index=self.visit(node.index))
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        return node

    def visit_script_block(self, node: ScriptBlockNode) -> ScriptBlockNode:
        simplified_stmts: List[ASTNode] = []

        for stmt in node.statements:
            res = self.visit(stmt)
            if res is not None:
                # If res is an inlined ScriptBlock with multiple statements, flatten them
                if isinstance(res, ScriptBlockNode) and res.is_nested and not node.is_nested:
                    simplified_stmts.extend(res.statements)
                else:
                    simplified_stmts.append(res)

        return ScriptBlockNode(statements=simplified_stmts, is_nested=node.is_nested)

    def visit_if_statement(self, node: IfStatementNode) -> Optional[ASTNode]:
        cond = self.visit(node.condition)
        then_b = self.visit(node.then_branch)
        else_b = self.visit(node.else_branch) if node.else_branch else None

        truthiness = self._eval_condition_truthiness(cond)

        if truthiness is True:
            # Positive branch is active; eliminate dead else branch
            return self._unwrap_branch_node(then_b)

        if truthiness is False:
            # Condition is false; active branch is else if present, otherwise dead code
            if else_b is not None:
                return self._unwrap_branch_node(else_b)
            return None  # Drop statement completely

        return IfStatementNode(condition=cond, then_branch=then_b, else_branch=else_b)

    def visit_while_statement(self, node: WhileStatementNode) -> Optional[ASTNode]:
        cond = self.visit(node.condition)
        body = self.visit(node.body)

        truthiness = self._eval_condition_truthiness(cond)
        if truthiness is False:
            # Loop condition is statically false; drop dead loop
            return None

        return WhileStatementNode(condition=cond, body=body)

    def visit_command(self, node: CommandNode) -> ASTNode:
        target = self.visit(node.target)
        arguments = [self.visit(a) for a in node.arguments]

        # 1. Unwrapping call operator: & { ... } or . { ... }
        if isinstance(target, IdentifierNode) and target.name in ("&", "."):
            if len(arguments) == 1:
                arg = arguments[0]
                inner_sb = self._extract_script_block(arg)
                if inner_sb is not None:
                    if len(inner_sb.statements) == 1:
                        return inner_sb.statements[0]
                    return inner_sb
            elif len(arguments) > 1:
                arg = arguments[0]
                inner_sb = self._extract_script_block(arg)
                if inner_sb is not None and len(inner_sb.statements) == 1:
                    first_stmt = inner_sb.statements[0]
                    # If scriptblock statement was a command, propagate extra arguments
                    if isinstance(first_stmt, CommandNode):
                        return CommandNode(
                            target=first_stmt.target,
                            arguments=first_stmt.arguments + arguments[1:],
                        )
                    elif isinstance(first_stmt, (IdentifierNode, StringLiteralNode)):
                        cmd_name = getattr(first_stmt, "name", getattr(first_stmt, "value", ""))
                        return CommandNode(
                            target=IdentifierNode(name=cmd_name),
                            arguments=arguments[1:],
                        )

        # 2. Fallback command-form: if (cond) { then } else { else }
        if isinstance(target, IdentifierNode) and target.name.lower() == "if":
            if len(arguments) >= 2:
                cond = arguments[0]
                then_b = arguments[1]
                else_b = arguments[3] if len(arguments) >= 4 and getattr(arguments[2], "name", "").lower() == "else" else None
                truthiness = self._eval_condition_truthiness(cond)
                if truthiness is True:
                    return self._unwrap_branch_node(then_b)
                if truthiness is False:
                    if else_b:
                        return self._unwrap_branch_node(else_b)
                    return ScriptBlockNode(statements=[], is_nested=True)

        return CommandNode(target=target, arguments=arguments)

    def visit_method_call(self, node: MethodCallNode) -> ASTNode:
        target = self.visit(node.target)
        arguments = [self.visit(a) for a in node.arguments]

        # ScriptBlock .Invoke() reduction: { ... }.Invoke()
        if node.method_name.lower() == "invoke" and not arguments:
            inner_sb = self._extract_script_block(target)
            if inner_sb is not None:
                if len(inner_sb.statements) == 1:
                    return inner_sb.statements[0]
                return inner_sb

        return MethodCallNode(target=target, method_name=node.method_name, arguments=arguments)

    def visit_assignment(self, node: AssignmentNode) -> AssignmentNode:
        expr = self.visit(node.expression)
        var_name = node.variable.name.lower()

        # Track ScriptBlock assignments: $sb = { ... }
        if isinstance(expr, ScriptBlockNode):
            self.symbols[var_name] = expr

        return AssignmentNode(variable=node.variable, expression=expr)

    def visit_pipeline(self, node: PipelineNode) -> ASTNode:
        norm_elements = [self.visit(e) for e in node.elements]
        if len(norm_elements) == 1:
            return norm_elements[0]
        return PipelineNode(elements=norm_elements)

    def visit_parenthesized(self, node: ParenthesizedExpressionNode) -> ASTNode:
        inner = self.visit(node.expression)
        if isinstance(inner, (StringLiteralNode, NumberLiteralNode, IdentifierNode)):
            return inner
        return ParenthesizedExpressionNode(expression=inner)

    def _extract_script_block(self, node: ASTNode) -> Optional[ScriptBlockNode]:
        """Resolves ScriptBlock directly, from parentheses, or from symbol table."""
        if isinstance(node, ScriptBlockNode):
            return node
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_script_block(node.expression)
        if isinstance(node, VariableNode):
            val = self.symbols.get(node.name.lower())
            if isinstance(val, ScriptBlockNode):
                return val
        return None

    def _unwrap_branch_node(self, node: ASTNode) -> ASTNode:
        """Unwraps a branch if it consists of a single statement."""
        if isinstance(node, ScriptBlockNode) and len(node.statements) == 1:
            return node.statements[0]
        return node

    def _eval_condition_truthiness(self, node: ASTNode) -> Optional[bool]:
        """Evaluates static truthiness of conditional expressions."""
        if isinstance(node, ParenthesizedExpressionNode):
            return self._eval_condition_truthiness(node.expression)

        # Variables: $true, $false, $null
        if isinstance(node, VariableNode):
            name = node.name.lower()
            if name == "true":
                return True
            if name in ("false", "null"):
                return False

        # Boolean literals or number literals
        if isinstance(node, NumberLiteralNode):
            return node.value != 0

        # String literals: "" is falsy, non-empty is truthy
        if isinstance(node, StringLiteralNode):
            return len(node.value) > 0

        # Unary not: !expr or -not expr
        if isinstance(node, UnaryOpNode):
            op = node.operator.lower()
            if op in ("-not", "!"):
                inner_truth = self._eval_condition_truthiness(node.operand)
                if inner_truth is not None:
                    return not inner_truth

        # Binary comparison operators
        if isinstance(node, BinaryOpNode):
            op = node.operator.lower()
            l_val = self._extract_literal_value(node.left)
            r_val = self._extract_literal_value(node.right)

            if l_val is not None and r_val is not None:
                if op == "-eq":
                    return l_val == r_val
                elif op == "-ne":
                    return l_val != r_val
                elif op == "-gt":
                    return l_val > r_val
                elif op == "-ge":
                    return l_val >= r_val
                elif op == "-lt":
                    return l_val < r_val
                elif op == "-le":
                    return l_val <= r_val

        return None

    def _extract_literal_value(self, node: ASTNode) -> Any:
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_literal_value(node.expression)
        if isinstance(node, (NumberLiteralNode, StringLiteralNode)):
            return node.value
        if isinstance(node, VariableNode):
            if node.name.lower() == "true":
                return True
            if node.name.lower() == "false":
                return False
            if node.name.lower() == "null":
                return None
        return None
