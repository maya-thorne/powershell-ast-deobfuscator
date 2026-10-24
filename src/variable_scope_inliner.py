"""
PowerShell Variable Scope Inliner & Constant Propagation Engine.
Performs scope-aware constant propagation, cmdlet rewriting (Get-Variable / Set-Variable),
dead variable elimination, and symbol table normalization.
"""

from typing import Any, Dict, List, Optional

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
from .scope_chain import PowerShellScopeChain
from .scope_models import ScopeAnalysisSummary, ScopeFrame, ScopeType
from .variable_lifecycle_tracker import PowerShellVariableLifecycleTracker


class PowerShellVariableScopeInliner:
    """
    Transforms PowerShell AST using scope-level symbol analysis:
    - Inlines constant variables respecting scope hierarchy and shadowing.
    - Resolves and rewrites Get-Variable / Set-Variable cmdlets.
    - Optionally eliminates dead variable assignments with zero side-effects.
    """

    def __init__(
        self,
        symbols: Optional[Dict[str, Any]] = None,
        propagate_constants: bool = True,
        eliminate_dead_vars: bool = False,
    ):
        self.symbols = symbols if symbols is not None else {}
        self.propagate_constants = propagate_constants
        self.eliminate_dead_vars = eliminate_dead_vars
        self.last_summary: Optional[ScopeAnalysisSummary] = None
        self._current_frame: Optional[ScopeFrame] = None
        self._frame_stack: List[ScopeFrame] = []
        self._chain: Optional[PowerShellScopeChain] = None

    def inline(self, ast: ASTNode) -> ASTNode:
        """
        Executes scope analysis and inlines constant variables across the AST.
        """
        # Phase 1: Build complete scope chain and symbol tables
        tracker = PowerShellVariableLifecycleTracker(initial_symbols=self.symbols)
        self.last_summary = tracker.analyze(ast)
        self._chain = tracker.chain

        # Phase 2: Traverse and rewrite AST with active scope tracking
        self._frame_stack = [self._chain.global_frame, self._chain.script_frame]
        self._current_frame = self._chain.script_frame
        return self.visit(ast)

    def visit(self, node: Optional[ASTNode]) -> ASTNode:
        if node is None:
            return None

        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        elif isinstance(node, AssignmentNode):
            return self.visit_assignment(node)
        elif isinstance(node, VariableNode):
            return self.visit_variable(node)
        elif isinstance(node, CommandNode):
            return self.visit_command(node)
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, ForEachStatementNode):
            return self.visit_foreach(node)
        elif isinstance(node, ForStatementNode):
            return self.visit_for(node)
        elif isinstance(node, WhileStatementNode):
            return self.visit_while(node)
        elif isinstance(node, IfStatementNode):
            return self.visit_if(node)
        elif isinstance(node, BinaryOpNode):
            return BinaryOpNode(left=self.visit(node.left), operator=node.operator, right=self.visit(node.right))
        elif isinstance(node, UnaryOpNode):
            return UnaryOpNode(operator=node.operator, operand=self.visit(node.operand))
        elif isinstance(node, FormatOpNode):
            return FormatOpNode(
                format_string=self.visit(node.format_string),
                arguments=[self.visit(a) for a in node.arguments],
            )
        elif isinstance(node, ParenthesizedExpressionNode):
            rewritten_expr = self.visit(node.expression)
            # Unbox (Get-Variable x).Value patterns
            if isinstance(rewritten_expr, VariableNode):
                return rewritten_expr
            return ParenthesizedExpressionNode(expression=rewritten_expr)
        elif isinstance(node, RangeExpressionNode):
            return RangeExpressionNode(start=self.visit(node.start), end=self.visit(node.end))
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        elif isinstance(node, TypeCastNode):
            return TypeCastNode(type_name=node.type_name, expression=self.visit(node.expression))
        elif isinstance(node, MemberAccessNode):
            return self.visit_member_access(node)
        elif isinstance(node, StaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)
        elif isinstance(node, MethodCallNode):
            return MethodCallNode(
                target=self.visit(node.target),
                method_name=node.method_name,
                arguments=[self.visit(a) for a in node.arguments],
            )
        elif isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self.visit(node.target), index=self.visit(node.index))
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
        elif isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self.visit(s) for s in node.statements])
        elif isinstance(node, CoalesceExpressionNode):
            return CoalesceExpressionNode(left=self.visit(node.left), right=self.visit(node.right))
        elif isinstance(node, CoalesceAssignmentNode):
            return CoalesceAssignmentNode(variable=self.visit(node.variable), expression=self.visit(node.expression))
        elif isinstance(node, TernaryExpressionNode):
            return TernaryExpressionNode(
                condition=self.visit(node.condition),
                if_true=self.visit(node.if_true),
                if_false=self.visit(node.if_false),
            )

        return node

    def visit_script_block(self, node: ScriptBlockNode) -> ASTNode:
        if node.is_nested and self._chain:
            # Advance to matching child frame
            child_frame: Optional[ScopeFrame] = None
            if self._current_frame and self._current_frame.children:
                # Find matching child frame
                for ch in self._current_frame.children:
                    if ch not in self._frame_stack:
                        child_frame = ch
                        break

            if child_frame:
                self._frame_stack.append(child_frame)
                self._current_frame = child_frame

            norm_stmts: List[ASTNode] = []
            for stmt in node.statements:
                rewritten = self.visit(stmt)
                if rewritten is not None:
                    norm_stmts.append(rewritten)

            if child_frame and len(self._frame_stack) > 2:
                self._frame_stack.pop()
                self._current_frame = self._frame_stack[-1]

            return ScriptBlockNode(statements=norm_stmts, is_nested=True)
        else:
            norm_stmts = []
            for stmt in node.statements:
                rewritten = self.visit(stmt)
                if rewritten is not None:
                    norm_stmts.append(rewritten)
            return ScriptBlockNode(statements=norm_stmts, is_nested=False)

    def visit_assignment(self, node: AssignmentNode) -> Optional[ASTNode]:
        target = node.variable
        norm_expr = self.visit(node.expression)

        if isinstance(target, VariableNode):
            clean_name = target.name.lstrip("$").replace("`", "")
            norm_target = VariableNode(name=clean_name, scope=target.scope)

            # Optional Dead Variable Assignment Elimination
            if self.eliminate_dead_vars and self._is_side_effect_free(norm_expr):
                # Check if this variable's definitions are all dead
                sym = self._lookup_symbol(clean_name, target.scope)
                if sym and sym.is_dead and len(sym.reads) == 0:
                    # Drop dead assignment entirely
                    return None

            return AssignmentNode(variable=norm_target, expression=norm_expr)

        return AssignmentNode(variable=self.visit(target), expression=norm_expr)

    def visit_variable(self, node: VariableNode) -> ASTNode:
        clean_name = node.name.lstrip("$").replace("`", "")

        # Skip automatic and special variables that environment_inliner manages
        special_names = ("true", "false", "null", "_", "this", "psitem", "args")
        if clean_name.lower() in special_names:
            return VariableNode(name=clean_name, scope=node.scope)

        if self.propagate_constants:
            sym = self._lookup_symbol(clean_name, node.scope)
            if sym and sym.is_constant and sym.constant_value is not None:
                # Replace with literal constant
                val = sym.constant_value
                if isinstance(val, str):
                    return StringLiteralNode(value=val)
                elif isinstance(val, (int, float)):
                    return NumberLiteralNode(value=val, raw=str(val))

        return VariableNode(name=clean_name, scope=node.scope)

    def visit_member_access(self, node: MemberAccessNode) -> ASTNode:
        norm_target = self.visit(node.target)
        # Check (Get-Variable 'x').Value pattern
        if node.member.lower() == "value":
            if isinstance(norm_target, VariableNode):
                return norm_target
            if isinstance(norm_target, (StringLiteralNode, NumberLiteralNode)):
                return norm_target

        return MemberAccessNode(target=norm_target, member=node.member)

    def visit_command(self, node: CommandNode) -> ASTNode:
        cmd_name = ""
        if isinstance(node.target, IdentifierNode):
            cmd_name = node.target.name.lower()
        elif isinstance(node.target, StringLiteralNode):
            cmd_name = node.target.value.lower()

        # Handle Get-Variable / gv inlining
        if cmd_name in ("get-variable", "gv"):
            name_node = self._extract_cmd_named_arg(node.arguments, "name")
            scope_node = self._extract_cmd_named_arg(node.arguments, "scope")
            if not name_node and node.arguments:
                name_node = node.arguments[0]

            var_name = self._resolve_literal_str(name_node)
            scope_str = self._resolve_literal_str(scope_node)

            if var_name:
                var_ast = VariableNode(name=var_name, scope=scope_str)
                return self.visit_variable(var_ast)

        # Handle Set-Variable / sv rewriting to assignment
        if cmd_name in ("set-variable", "sv"):
            name_node = self._extract_cmd_named_arg(node.arguments, "name")
            val_node = self._extract_cmd_named_arg(node.arguments, "value")
            scope_node = self._extract_cmd_named_arg(node.arguments, "scope")

            if not name_node and node.arguments:
                name_node = node.arguments[0]
            if not val_node and len(node.arguments) > 1 and not (isinstance(node.arguments[1], IdentifierNode) and node.arguments[1].name.startswith("-")):
                val_node = node.arguments[1]

            var_name = self._resolve_literal_str(name_node)
            scope_str = self._resolve_literal_str(scope_node)

            if var_name and val_node:
                return self.visit_assignment(
                    AssignmentNode(
                        variable=VariableNode(name=var_name, scope=scope_str),
                        expression=self.visit(val_node),
                    )
                )

        norm_target = self.visit(node.target)
        norm_args = [self.visit(a) for a in node.arguments]
        return CommandNode(target=norm_target, arguments=norm_args)

    def visit_pipeline(self, node: PipelineNode) -> ASTNode:
        norm_elems = [self.visit(e) for e in node.elements]
        return PipelineNode(elements=norm_elems)

    def visit_foreach(self, node: ForEachStatementNode) -> ASTNode:
        norm_coll = self.visit(node.collection) if node.collection else None
        norm_var = self.visit(node.variable) if node.variable else None
        norm_body = self.visit(node.body) if node.body else None
        return ForEachStatementNode(variable=norm_var, collection=norm_coll, body=norm_body)

    def visit_for(self, node: ForStatementNode) -> ASTNode:
        norm_init = self.visit(node.initializer) if node.initializer else None
        norm_cond = self.visit(node.condition) if node.condition else None
        norm_iter = self.visit(node.iterator) if node.iterator else None
        norm_body = self.visit(node.body) if node.body else None
        return ForStatementNode(initializer=norm_init, condition=norm_cond, iterator=norm_iter, body=norm_body)

    def visit_while(self, node: WhileStatementNode) -> ASTNode:
        norm_cond = self.visit(node.condition) if node.condition else None
        norm_body = self.visit(node.body) if node.body else None
        return WhileStatementNode(condition=norm_cond, body=norm_body)

    def visit_if(self, node: IfStatementNode) -> ASTNode:
        norm_cond = self.visit(node.condition) if node.condition else None
        norm_then = self.visit(node.then_branch) if node.then_branch else None
        norm_else = self.visit(node.else_branch) if node.else_branch else None
        return IfStatementNode(condition=norm_cond, then_branch=norm_then, else_branch=norm_else)

    def _lookup_symbol(self, name: str, scope_qualifier: Optional[str]) -> Optional[Any]:
        if not self._chain:
            return None

        key = name.lower()
        if scope_qualifier:
            target_frame = self._chain.resolve_target_frame(scope_qualifier)
            return target_frame.get_symbol(key)

        # Walk up from current active frame
        curr: Optional[ScopeFrame] = self._current_frame
        while curr is not None:
            sym = curr.get_symbol(key)
            if sym is not None:
                if sym.is_private and curr.scope_id != (self._current_frame.scope_id if self._current_frame else -1):
                    curr = curr.parent
                    continue
                return sym
            curr = curr.parent

        return None

    def _is_side_effect_free(self, node: ASTNode) -> bool:
        """Determines if an expression is pure and safe to drop when dead."""
        if isinstance(node, (StringLiteralNode, NumberLiteralNode, IdentifierNode, VariableNode)):
            return True
        if isinstance(node, BinaryOpNode):
            return self._is_side_effect_free(node.left) and self._is_side_effect_free(node.right)
        if isinstance(node, UnaryOpNode):
            return self._is_side_effect_free(node.operand)
        if isinstance(node, ArrayLiteralNode):
            return all(self._is_side_effect_free(e) for e in node.elements)
        if isinstance(node, ParenthesizedExpressionNode):
            return self._is_side_effect_free(node.expression)
        return False

    def _extract_cmd_named_arg(self, args: List[ASTNode], param_name: str) -> Optional[ASTNode]:
        for i, a in enumerate(args):
            if isinstance(a, IdentifierNode) and a.name.lower() == f"-{param_name.lower()}":
                if i + 1 < len(args):
                    return args[i + 1]
        return None

    def _resolve_literal_str(self, node: Optional[ASTNode]) -> Optional[str]:
        if isinstance(node, StringLiteralNode):
            return node.value
        elif isinstance(node, IdentifierNode):
            return node.name
        elif isinstance(node, VariableNode):
            return node.name
        return None
