"""
PowerShell Subexpression ($(...)) Unwrapper & Reducer.
Unboxes redundant nested subexpressions, folds subexpression string concatenations,
interpolates expandable strings with embedded subexpressions, and evaluates multi-statement blocks.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

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


class PowerShellSubexpressionUnwrapper:
    """
    Traverses PowerShell AST hierarchies to unbox and reduce subexpressions:
    1. Unboxes redundant nested subexpressions: $((('cmd.exe'))) -> 'cmd.exe'
    2. Simplifies subexpression concatenations: $('i') + $('e') + $('x') -> 'iex'
    3. Interpolates expandable strings: "$('Invoke')-$('Expression')" -> 'Invoke-Expression'
    4. Evaluates multi-statement subexpressions: $($x = 'calc'; $x) -> 'calc'
    5. Preserves complex non-trivial multi-statement pipelines and control flows.
    """

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols = symbols if symbols is not None else {}

    def unwrap(self, node: ASTNode) -> ASTNode:
        """Entry point for subexpression AST unwrapping and reduction."""
        return self.visit(node)

    def visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        elif isinstance(node, SubexpressionNode):
            return self.visit_subexpression(node)
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, CommandNode):
            return self.visit_command(node)
        elif isinstance(node, AssignmentNode):
            return self.visit_assignment(node)
        elif isinstance(node, ParenthesizedExpressionNode):
            return self.visit_parenthesized(node)
        elif isinstance(node, BinaryOpNode):
            return self.visit_binary_op(node)
        elif isinstance(node, UnaryOpNode):
            return self.visit_unary_op(node)
        elif isinstance(node, IndexAccessNode):
            return self.visit_index_access(node)
        elif isinstance(node, StringLiteralNode):
            return self.visit_string_literal(node)
        elif isinstance(node, VariableNode):
            return self.visit_variable(node)
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
            return MethodCallNode(
                target=self.visit(node.target),
                method_name=node.method_name,
                arguments=[self.visit(a) for a in node.arguments],
            )
        elif isinstance(node, DynamicMemberAccessNode):
            return DynamicMemberAccessNode(target=self.visit(node.target), member_expr=self.visit(node.member_expr))
        elif isinstance(node, DynamicMethodCallNode):
            return DynamicMethodCallNode(
                target=self.visit(node.target),
                method_expr=self.visit(node.method_expr),
                arguments=[self.visit(a) for a in node.arguments],
            )
        elif isinstance(node, DynamicStaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return DynamicStaticMemberAccessNode(
                type_name=node.type_name,
                member_expr=self.visit(node.member_expr),
                arguments=norm_args,
            )
        elif isinstance(node, RangeExpressionNode):
            return RangeExpressionNode(start=self.visit(node.start), end=self.visit(node.end))
        elif isinstance(node, FormatOpNode):
            return FormatOpNode(
                format_string=self.visit(node.format_string),
                arguments=[self.visit(a) for a in node.arguments],
            )
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
        return ScriptBlockNode(
            statements=[self.visit(s) for s in node.statements],
            is_nested=node.is_nested,
        )

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
        val = self._eval_const(norm_expr)
        if val is not None and node.variable.scope in (None, "local", "script", "global"):
            self.symbols[node.variable.name.lower()] = val
        return AssignmentNode(variable=node.variable, expression=norm_expr)

    def visit_parenthesized(self, node: ParenthesizedExpressionNode) -> ASTNode:
        norm_inner = self.visit(node.expression)
        if isinstance(norm_inner, (StringLiteralNode, NumberLiteralNode, IdentifierNode)):
            return norm_inner
        return ParenthesizedExpressionNode(expression=norm_inner)

    def visit_variable(self, node: VariableNode) -> ASTNode:
        if node.scope in (None, "local", "script", "global"):
            var_key = node.name.lower()
            if var_key in self.symbols:
                val = self.symbols[var_key]
                if isinstance(val, str):
                    return StringLiteralNode(value=val, is_expandable=False)
                elif isinstance(val, (int, float)):
                    return NumberLiteralNode(value=val, raw=str(val))
        return node

    def visit_subexpression(self, node: SubexpressionNode) -> ASTNode:
        """
        Unboxes redundant subexpressions:
        - Single literal/variable/command: $( 'calc.exe' ) -> 'calc.exe'
        - Nested subexpressions: $((('cmd.exe'))) -> 'cmd.exe'
        - Multi-statement variable assignments: $($a = 'calc'; $a) -> 'calc'
        - Preserves complex multi-statement pipelines if non-trivial.
        """
        if not node.statements:
            return StringLiteralNode(value="", is_expandable=False)

        # 1. Single statement subexpression
        if len(node.statements) == 1:
            stmt = self.visit(node.statements[0])

            # Strip redundant parenthesized wrapping inside subexpression
            while isinstance(stmt, ParenthesizedExpressionNode):
                stmt = self.visit(stmt.expression)

            # Strip redundant nested subexpressions: $($(expr))
            while isinstance(stmt, SubexpressionNode) and len(stmt.statements) == 1:
                stmt = self.visit(stmt.statements[0])
                while isinstance(stmt, ParenthesizedExpressionNode):
                    stmt = self.visit(stmt.expression)

            # If inner statement is a simple unboxable construct, unbox directly
            if isinstance(
                stmt,
                (
                    StringLiteralNode,
                    NumberLiteralNode,
                    VariableNode,
                    IdentifierNode,
                    BinaryOpNode,
                    UnaryOpNode,
                    FormatOpNode,
                    ArrayLiteralNode,
                    TypeCastNode,
                    MemberAccessNode,
                    MethodCallNode,
                    StaticMemberAccessNode,
                    IndexAccessNode,
                    CommandNode,
                ),
            ):
                return stmt

            if isinstance(stmt, PipelineNode):
                if len(stmt.elements) == 1:
                    return stmt.elements[0]
                return stmt

            return SubexpressionNode(statements=[stmt])

        # 2. Multi-statement subexpression evaluation: $($a = 'cmd'; $a)
        local_symbols = dict(self.symbols)
        can_reduce = True
        evaluated_stmts: List[ASTNode] = []

        for stmt in node.statements[:-1]:
            norm_stmt = self.visit(stmt)
            evaluated_stmts.append(norm_stmt)
            if isinstance(norm_stmt, AssignmentNode):
                val = self._eval_const(norm_stmt.expression)
                if val is not None:
                    local_symbols[norm_stmt.variable.name.lower()] = val
                    self.symbols[norm_stmt.variable.name.lower()] = val
                else:
                    can_reduce = False
            else:
                can_reduce = False

        last_stmt = self.visit(node.statements[-1])
        evaluated_stmts.append(last_stmt)

        if can_reduce:
            # Trailing variable reference
            if isinstance(last_stmt, VariableNode):
                var_key = last_stmt.name.lower()
                if var_key in local_symbols:
                    val = local_symbols[var_key]
                    if isinstance(val, str):
                        return StringLiteralNode(value=val, is_expandable=False)
                    elif isinstance(val, (int, float)):
                        return NumberLiteralNode(value=val, raw=str(val))

            # Trailing literal or resolved expression
            last_const = self._eval_const(last_stmt)
            if last_const is not None:
                if isinstance(last_const, str):
                    return StringLiteralNode(value=last_const, is_expandable=False)
                elif isinstance(last_const, (int, float)):
                    return NumberLiteralNode(value=last_const, raw=str(last_const))

        return SubexpressionNode(statements=evaluated_stmts)

    def visit_binary_op(self, node: BinaryOpNode) -> ASTNode:
        left = self.visit(node.left)
        right = self.visit(node.right)

        # Unbox SubexpressionNode operands if single literal
        if isinstance(left, SubexpressionNode) and len(left.statements) == 1:
            left = self.visit(left.statements[0])
        if isinstance(right, SubexpressionNode) and len(right.statements) == 1:
            right = self.visit(right.statements[0])

        # Subexpression string concatenation folding: $('i') + $('e') + $('x') -> 'iex'
        if node.operator == "+":
            if isinstance(left, StringLiteralNode) and isinstance(right, StringLiteralNode):
                return StringLiteralNode(
                    value=left.value + right.value,
                    is_expandable=left.is_expandable and right.is_expandable,
                )

        # -join operator evaluation
        if node.operator.lower() == "-join":
            inner_left = left.expression if isinstance(left, ParenthesizedExpressionNode) else left
            delim = right.value if isinstance(right, StringLiteralNode) else ""
            if isinstance(inner_left, ArrayLiteralNode):
                if all(isinstance(e, (StringLiteralNode, NumberLiteralNode)) for e in inner_left.elements):
                    joined = delim.join(str(e.value) for e in inner_left.elements)
                    return StringLiteralNode(value=joined, is_expandable=False)
            elif isinstance(inner_left, StringLiteralNode):
                return inner_left

        return BinaryOpNode(left=left, operator=node.operator, right=right)

    def visit_unary_op(self, node: UnaryOpNode) -> ASTNode:
        operand = self.visit(node.operand)
        if isinstance(operand, SubexpressionNode) and len(operand.statements) == 1:
            operand = self.visit(operand.statements[0])

        if node.operator.lower() == "-join":
            inner = operand.expression if isinstance(operand, ParenthesizedExpressionNode) else operand
            if isinstance(inner, ArrayLiteralNode):
                if all(isinstance(e, (StringLiteralNode, NumberLiteralNode)) for e in inner.elements):
                    joined = "".join(str(e.value) for e in inner.elements)
                    return StringLiteralNode(value=joined, is_expandable=False)
            elif isinstance(inner, StringLiteralNode):
                return inner

        return UnaryOpNode(operator=node.operator, operand=operand)

    def visit_index_access(self, node: IndexAccessNode) -> ASTNode:
        """Evaluates array or string indexing off subexpression: $('hello')[1] -> 'e'."""
        target = self.visit(node.target)
        index = self.visit(node.index)

        # Unbox if target was a subexpression
        if isinstance(target, SubexpressionNode) and len(target.statements) == 1:
            target = self.visit(target.statements[0])
        if isinstance(target, ParenthesizedExpressionNode):
            target = target.expression

        if isinstance(index, ParenthesizedExpressionNode):
            index = index.expression

        if isinstance(index, NumberLiteralNode):
            try:
                idx = int(index.value)
                if isinstance(target, StringLiteralNode):
                    if 0 <= idx < len(target.value):
                        return StringLiteralNode(value=target.value[idx], is_expandable=False)
                elif isinstance(target, ArrayLiteralNode):
                    if 0 <= idx < len(target.elements):
                        return target.elements[idx]
            except ValueError:
                pass

        return IndexAccessNode(target=target, index=index)

    def visit_string_literal(self, node: StringLiteralNode) -> ASTNode:
        """
        Unwraps expandable strings containing embedded subexpressions:
        "prefix $( 'foo' ) suffix" -> "prefix foo suffix"
        "$('In'+'voke')-$('Ex'+'pression')" -> 'Invoke-Expression'
        """
        if "$(" not in node.value:
            return node

        new_val, has_unresolved = self._unwrap_embedded_subexpressions(node.value)
        # If all subexpressions were resolved and string has no remaining variable markers
        if not has_unresolved and not re.search(r"(?<!`)\$[A-Za-z0-9_:]+", new_val):
            return StringLiteralNode(value=new_val, is_expandable=False)

        return StringLiteralNode(value=new_val, is_expandable=node.is_expandable)

    def _unwrap_embedded_subexpressions(self, text: str) -> Tuple[str, bool]:
        """
        Extracts and evaluates embedded $( ... ) constructs inside expandable strings.
        Returns (interpolated_text, has_unresolved).
        """
        spans = self._extract_top_level_subexpressions(text)
        if not spans:
            return text, False

        result = []
        last_idx = 0
        has_unresolved = False

        for start, end, inner_code in spans:
            result.append(text[last_idx:start])
            eval_val = self._evaluate_subexpr_code(inner_code)
            if eval_val is not None:
                result.append(eval_val)
            else:
                result.append(text[start:end])
                has_unresolved = True
            last_idx = end

        result.append(text[last_idx:])
        return "".join(result), has_unresolved

    def _extract_top_level_subexpressions(self, text: str) -> List[Tuple[int, int, str]]:
        """Finds top-level $( ... ) index ranges with parenthesis and quote balancing."""
        spans: List[Tuple[int, int, str]] = []
        i = 0
        n = len(text)

        while i < n:
            if text[i : i + 2] == "$(":
                start = i
                i += 2
                depth = 1
                inner_start = i
                in_single = False
                in_double = False

                while i < n and depth > 0:
                    ch = text[i]
                    if in_single:
                        if ch == "'":
                            if i + 1 < n and text[i + 1] == "'":
                                i += 2
                                continue
                            in_single = False
                        i += 1
                        continue

                    if in_double:
                        if ch == "`":
                            i += 2
                            continue
                        if ch == '"':
                            in_double = False
                        i += 1
                        continue

                    if ch == "'":
                        in_single = True
                        i += 1
                    elif ch == '"':
                        in_double = True
                        i += 1
                    elif ch == "(":
                        depth += 1
                        i += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            spans.append((start, i + 1, text[inner_start:i]))
                        i += 1
                    else:
                        i += 1
            else:
                i += 1

        return spans

    def _evaluate_subexpr_code(self, code: str) -> Optional[str]:
        """Parses and reduces a subexpression code string to a constant string if possible."""
        try:
            tokens = PowerShellLexer(code).tokenize()
            parser = PowerShellParser(tokens)
            ast = parser.parse()
            unwrapped_ast = self.unwrap(ast)

            if isinstance(unwrapped_ast, ScriptBlockNode):
                if len(unwrapped_ast.statements) == 1:
                    stmt = unwrapped_ast.statements[0]
                    const_val = self._eval_const(stmt)
                    if const_val is not None:
                        return str(const_val)
                elif len(unwrapped_ast.statements) > 1:
                    last_stmt = unwrapped_ast.statements[-1]
                    const_val = self._eval_const(last_stmt)
                    if const_val is not None:
                        return str(const_val)
            elif isinstance(unwrapped_ast, (StringLiteralNode, NumberLiteralNode)):
                return str(unwrapped_ast.value)
        except Exception:
            pass
        return None

    def _eval_const(self, node: ASTNode) -> Any:
        """Evaluates simple constant expressions or symbol references."""
        if isinstance(node, StringLiteralNode):
            return node.value
        if isinstance(node, NumberLiteralNode):
            return node.value
        if isinstance(node, VariableNode):
            return self.symbols.get(node.name.lower())
        if isinstance(node, ParenthesizedExpressionNode):
            return self._eval_const(node.expression)
        if isinstance(node, SubexpressionNode) and len(node.statements) == 1:
            return self._eval_const(node.statements[0])
        if isinstance(node, BinaryOpNode) and node.operator == "+":
            l_val = self._eval_const(node.left)
            r_val = self._eval_const(node.right)
            if isinstance(l_val, str) and isinstance(r_val, str):
                return l_val + r_val
            if isinstance(l_val, (int, float)) and isinstance(r_val, (int, float)):
                return l_val + r_val
        return None
