"""
PowerShell Variable Lifecycle Tracker & AST Traversal Engine.
Builds the hierarchical scope chain by analyzing variable assignments, usages,
variable cmdlets (Set-Variable, Get-Variable, New-Variable), loops, and function declarations.
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
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)
from .scope_chain import PowerShellScopeChain
from .scope_models import ScopeAnalysisSummary, ScopeType


class PowerShellVariableLifecycleTracker:
    """
    AST visitor that traverses code, populates the PowerShellScopeChain,
    and analyzes symbol lifecycles, def-use chains, and scope boundaries.
    """

    def __init__(self, initial_symbols: Optional[Dict[str, Any]] = None):
        self.chain = PowerShellScopeChain(initial_symbols=initial_symbols)
        self._statement_counter = 0

    def analyze(self, ast: ASTNode) -> ScopeAnalysisSummary:
        """
        Performs complete scope and lifecycle analysis over the AST.
        """
        self._statement_counter = 0
        self.visit(ast)
        return self.chain.finalize_analysis()

    def visit(self, node: Optional[ASTNode]) -> None:
        if node is None:
            return

        if isinstance(node, ScriptBlockNode):
            self.visit_script_block(node)
        elif isinstance(node, AssignmentNode):
            self.visit_assignment(node)
        elif isinstance(node, VariableNode):
            self.visit_variable(node)
        elif isinstance(node, CommandNode):
            self.visit_command(node)
        elif isinstance(node, PipelineNode):
            self.visit_pipeline(node)
        elif isinstance(node, ForEachStatementNode):
            self.visit_foreach(node)
        elif isinstance(node, ForStatementNode):
            self.visit_for(node)
        elif isinstance(node, WhileStatementNode):
            self.visit_while(node)
        elif isinstance(node, IfStatementNode):
            self.visit_if(node)
        elif isinstance(node, BinaryOpNode):
            self.visit(node.left)
            self.visit(node.right)
        elif isinstance(node, UnaryOpNode):
            self.visit(node.operand)
        elif isinstance(node, FormatOpNode):
            self.visit(node.format_string)
            for a in node.arguments:
                self.visit(a)
        elif isinstance(node, ParenthesizedExpressionNode):
            self.visit(node.expression)
        elif isinstance(node, RangeExpressionNode):
            self.visit(node.start)
            self.visit(node.end)
        elif isinstance(node, ArrayLiteralNode):
            for e in node.elements:
                self.visit(e)
        elif isinstance(node, TypeCastNode):
            self.visit(node.expression)
        elif isinstance(node, MemberAccessNode):
            self.visit(node.target)
        elif isinstance(node, StaticMemberAccessNode):
            if node.arguments:
                for a in node.arguments:
                    self.visit(a)
        elif isinstance(node, MethodCallNode):
            self.visit(node.target)
            for a in node.arguments:
                self.visit(a)
        elif isinstance(node, IndexAccessNode):
            self.visit(node.target)
            self.visit(node.index)
        elif isinstance(node, DynamicMemberAccessNode):
            self.visit(node.target)
            self.visit(node.member_expr)
        elif isinstance(node, DynamicMethodCallNode):
            self.visit(node.target)
            self.visit(node.method_expr)
            for a in node.arguments:
                self.visit(a)
        elif isinstance(node, DynamicStaticMemberAccessNode):
            self.visit(node.member_expr)
            if node.arguments:
                for a in node.arguments:
                    self.visit(a)
        elif isinstance(node, SubexpressionNode):
            for s in node.statements:
                self.visit(s)

    def visit_script_block(self, node: ScriptBlockNode) -> None:
        if node.is_nested:
            scope_name = f"block_{len(self.chain.all_frames)}"
            self.chain.push_scope(ScopeType.SCRIPT_BLOCK, scope_name)
            for stmt in node.statements:
                self._statement_counter += 1
                self.visit(stmt)
            self.chain.pop_scope()
        else:
            for stmt in node.statements:
                self._statement_counter += 1
                self.visit(stmt)

    def visit_assignment(self, node: AssignmentNode) -> None:
        self._statement_counter += 1
        # Evaluate right-hand side first (reads in expression)
        self.visit(node.expression)

        # Record assignment on target
        target = node.variable
        if isinstance(target, VariableNode):
            self.chain.resolve_write(
                var_name=target.name,
                scope_qualifier=target.scope,
                value_node=node.expression,
                ast_node=node,
                stmt_idx=self._statement_counter,
            )
        elif isinstance(target, (IndexAccessNode, MemberAccessNode)):
            # Target property/index write involves reading the root variable
            self.visit(target)
        else:
            self.visit(target)

    def visit_variable(self, node: VariableNode) -> None:
        self.chain.resolve_read(
            var_name=node.name,
            scope_qualifier=node.scope,
            ast_node=node,
            stmt_idx=self._statement_counter,
        )

    def visit_pipeline(self, node: PipelineNode) -> None:
        for elem in node.elements:
            self.visit(elem)

    def visit_foreach(self, node: ForEachStatementNode) -> None:
        # Collection evaluated in enclosing scope
        if node.collection:
            self.visit(node.collection)

        # Loop body runs in child scope
        self.chain.push_scope(ScopeType.SCRIPT_BLOCK, f"foreach_{len(self.chain.all_frames)}")
        if isinstance(node.variable, VariableNode):
            self.chain.resolve_write(
                var_name=node.variable.name,
                scope_qualifier=node.variable.scope,
                ast_node=node.variable,
                stmt_idx=self._statement_counter,
            )
        if node.body:
            self.visit(node.body)
        self.chain.pop_scope()

    def visit_for(self, node: ForStatementNode) -> None:
        self.chain.push_scope(ScopeType.SCRIPT_BLOCK, f"for_{len(self.chain.all_frames)}")
        if node.initializer:
            self.visit(node.initializer)
        if node.condition:
            self.visit(node.condition)
        if node.iterator:
            self.visit(node.iterator)
        if node.body:
            self.visit(node.body)
        self.chain.pop_scope()

    def visit_while(self, node: WhileStatementNode) -> None:
        if node.condition:
            self.visit(node.condition)
        self.chain.push_scope(ScopeType.SCRIPT_BLOCK, f"while_{len(self.chain.all_frames)}")
        if node.body:
            self.visit(node.body)
        self.chain.pop_scope()

    def visit_if(self, node: IfStatementNode) -> None:
        if node.condition:
            self.visit(node.condition)
        if node.then_branch:
            self.visit(node.then_branch)
        if node.else_branch:
            self.visit(node.else_branch)

    def visit_command(self, node: CommandNode) -> None:
        cmd_name = ""
        if isinstance(node.target, IdentifierNode):
            cmd_name = node.target.name.lower()
        elif isinstance(node.target, StringLiteralNode):
            cmd_name = node.target.value.lower()

        # Check PowerShell function declaration: function foo { ... } or filter foo { ... }
        if cmd_name in ("function", "filter") and node.arguments:
            self._handle_function_declaration(node)
            return

        # Check Variable cmdlets: Set-Variable, Get-Variable, New-Variable, Clear-Variable, Remove-Variable
        if cmd_name in ("set-variable", "sv"):
            self._handle_set_variable(node)
            return
        elif cmd_name in ("get-variable", "gv"):
            self._handle_get_variable(node)
            return
        elif cmd_name in ("new-variable", "nv"):
            self._handle_new_variable(node)
            return
        elif cmd_name in ("clear-variable", "clv"):
            self._handle_clear_variable(node)
            return
        elif cmd_name in ("remove-variable", "rv"):
            self._handle_remove_variable(node)
            return

        # General command: visit target and arguments
        self.visit(node.target)
        for a in node.arguments:
            self.visit(a)

    def _handle_function_declaration(self, node: CommandNode) -> None:
        func_name = "anonymous"
        body_node: Optional[ASTNode] = None

        if len(node.arguments) >= 2:
            arg0 = node.arguments[0]
            if isinstance(arg0, IdentifierNode):
                func_name = arg0.name
            elif isinstance(arg0, StringLiteralNode):
                func_name = arg0.value
            body_node = node.arguments[1]
        elif len(node.arguments) == 1:
            body_node = node.arguments[0]

        # Function scope frame
        self.chain.push_scope(ScopeType.FUNCTION, f"func:{func_name}")
        if body_node:
            self.visit(body_node)
        self.chain.pop_scope()

    def _extract_cmd_named_arg(self, args: List[ASTNode], param_name: str) -> Optional[ASTNode]:
        for i, a in enumerate(args):
            if isinstance(a, IdentifierNode) and a.name.lower() == f"-{param_name.lower()}":
                if i + 1 < len(args):
                    return args[i + 1]
        return None

    def _handle_set_variable(self, node: CommandNode) -> None:
        name_node = self._extract_cmd_named_arg(node.arguments, "name")
        val_node = self._extract_cmd_named_arg(node.arguments, "value")
        scope_node = self._extract_cmd_named_arg(node.arguments, "scope")

        # Fallback to positional: Set-Variable Name Value
        if not name_node and node.arguments:
            name_node = node.arguments[0]
        if not val_node and len(node.arguments) > 1 and not (isinstance(node.arguments[1], IdentifierNode) and node.arguments[1].name.startswith("-")):
            val_node = node.arguments[1]

        var_name = self._resolve_literal_str(name_node)
        scope_str = self._resolve_literal_str(scope_node)

        if val_node:
            self.visit(val_node)

        if var_name:
            self.chain.resolve_write(
                var_name=var_name,
                scope_qualifier=scope_str,
                value_node=val_node,
                ast_node=node,
                stmt_idx=self._statement_counter,
            )

    def _handle_get_variable(self, node: CommandNode) -> None:
        name_node = self._extract_cmd_named_arg(node.arguments, "name")
        scope_node = self._extract_cmd_named_arg(node.arguments, "scope")

        if not name_node and node.arguments:
            name_node = node.arguments[0]

        var_name = self._resolve_literal_str(name_node)
        scope_str = self._resolve_literal_str(scope_node)

        if var_name:
            self.chain.resolve_read(
                var_name=var_name,
                scope_qualifier=scope_str,
                ast_node=node,
                stmt_idx=self._statement_counter,
            )

    def _handle_new_variable(self, node: CommandNode) -> None:
        name_node = self._extract_cmd_named_arg(node.arguments, "name")
        val_node = self._extract_cmd_named_arg(node.arguments, "value")
        scope_node = self._extract_cmd_named_arg(node.arguments, "scope")
        opt_node = self._extract_cmd_named_arg(node.arguments, "option")

        if not name_node and node.arguments:
            name_node = node.arguments[0]

        var_name = self._resolve_literal_str(name_node)
        scope_str = self._resolve_literal_str(scope_node)
        opt_str = self._resolve_literal_str(opt_node) or ""

        is_const = "constant" in opt_str.lower() or "readonly" in opt_str.lower()

        if val_node:
            self.visit(val_node)

        if var_name:
            self.chain.resolve_write(
                var_name=var_name,
                scope_qualifier=scope_str,
                value_node=val_node,
                ast_node=node,
                stmt_idx=self._statement_counter,
                is_constant=is_const,
            )

    def _handle_clear_variable(self, node: CommandNode) -> None:
        name_node = self._extract_cmd_named_arg(node.arguments, "name")
        scope_node = self._extract_cmd_named_arg(node.arguments, "scope")

        if not name_node and node.arguments:
            name_node = node.arguments[0]

        var_name = self._resolve_literal_str(name_node)
        scope_str = self._resolve_literal_str(scope_node)

        if var_name:
            self.chain.clear_variable(var_name, scope_qualifier=scope_str)

    def _handle_remove_variable(self, node: CommandNode) -> None:
        name_node = self._extract_cmd_named_arg(node.arguments, "name")
        scope_node = self._extract_cmd_named_arg(node.arguments, "scope")

        if not name_node and node.arguments:
            name_node = node.arguments[0]

        var_name = self._resolve_literal_str(name_node)
        scope_str = self._resolve_literal_str(scope_node)

        if var_name:
            self.chain.remove_variable(var_name, scope_qualifier=scope_str)

    def _resolve_literal_str(self, node: Optional[ASTNode]) -> Optional[str]:
        if isinstance(node, StringLiteralNode):
            return node.value
        elif isinstance(node, IdentifierNode):
            return node.name
        elif isinstance(node, VariableNode):
            return node.name
        return None
