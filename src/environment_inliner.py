"""
PowerShell Environment Variable & ExecutionContext Inlining Engine.
Performs constant propagation for special environment variables ($env:COMSPEC, $env:PATH),
automatic variables ($PSHOME, $ShellId, $ExecutionContext), and ExecutionContext method invocations.
"""

import os
import re
from typing import Any, Dict, List, Optional

from .ast_nodes import (
    ASTNode,
    ArrayLiteralNode,
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
    FormatOpNode,
    IdentifierNode,
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
)
from .lexer import PowerShellLexer
from .parser import PowerShellParser


class PowerShellEnvironmentInliner:
    """
    Inlines standard and custom environment variables, special PowerShell variables,
    and ExecutionContext methods with constant propagation.
    """

    DEFAULT_ENV_VARS: Dict[str, str] = {
        "COMSPEC": r"C:\Windows\system32\cmd.exe",
        "PATH": "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "SYSTEMDRIVE": "C:",
        "HOMEDRIVE": "C:",
        "HOMEPATH": r"\Users\Administrator",
        "USERPROFILE": r"C:\Users\Administrator",
        "PUBLIC": r"C:\Users\Public",
        "ALLUSERSPROFILE": r"C:\ProgramData",
        "PROGRAMDATA": r"C:\ProgramData",
        "PROGRAMFILES": r"C:\Program Files",
        "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
        "COMMONPROGRAMFILES": r"C:\Program Files\Common Files",
        "COMMONPROGRAMFILES(X86)": r"C:\Program Files (x86)\Common Files",
        "OS": "Windows_NT",
        "TEMP": r"C:\Users\Administrator\AppData\Local\Temp",
        "TMP": r"C:\Users\Administrator\AppData\Local\Temp",
        "USERNAME": "Administrator",
        "COMPUTERNAME": "DESKTOP",
        "PSMODULEPATH": r"C:\Users\Administrator\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules",
    }

    DEFAULT_SPECIAL_VARS: Dict[str, str] = {
        "PSHOME": r"C:\Windows\System32\WindowsPowerShell\v1.0",
        "SHELLID": "Microsoft.PowerShell",
        "HOST": "System.Management.Automation.Internal.Host.InternalHost",
        "EXECUTIONCONTEXT": "System.Management.Automation.EngineIntrinsics",
        "VERBOSEPREFERENCE": "SilentlyContinue",
        "CONFIRMPREFERENCE": "High",
        "DEBUGPREFERENCE": "SilentlyContinue",
        "ERRORACTIONPREFERENCE": "Continue",
        "PROGRESSPREFERENCE": "Continue",
        "WARNINGPREFERENCE": "Continue",
        "WHATIFPREFERENCE": "False",
    }

    def __init__(
        self,
        symbols: Optional[Dict[str, Any]] = None,
        env: Optional[Dict[str, str]] = None,
        enable_system_env: bool = False,
    ):
        self.symbols = symbols if symbols is not None else {}
        self.env_vars: Dict[str, str] = dict(self.DEFAULT_ENV_VARS)
        if enable_system_env:
            for k, v in os.environ.items():
                self.env_vars[k.upper()] = v
        if env:
            for k, v in env.items():
                self.env_vars[k.upper()] = v
        self.special_vars: Dict[str, str] = dict(self.DEFAULT_SPECIAL_VARS)

    def inline(self, node: ASTNode) -> ASTNode:
        """Entry point for environment variable and ExecutionContext inlining."""
        return self.visit(node)

    def visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        elif isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self.visit(s) for s in node.statements])
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, CommandNode):
            return self.visit_command(node)
        elif isinstance(node, AssignmentNode):
            return self.visit_assignment(node)
        elif isinstance(node, VariableNode):
            return self.visit_variable(node)
        elif isinstance(node, MemberAccessNode):
            return self.visit_member_access(node)
        elif isinstance(node, MethodCallNode):
            return self.visit_method_call(node)
        elif isinstance(node, IndexAccessNode):
            return self.visit_index_access(node)
        elif isinstance(node, UnaryOpNode):
            return self.visit_unary_op(node)
        elif isinstance(node, BinaryOpNode):
            return self.visit_binary_op(node)
        elif isinstance(node, FormatOpNode):
            return self.visit_format_op(node)
        elif isinstance(node, ParenthesizedExpressionNode):
            return self.visit_parenthesized(node)
        elif isinstance(node, StringLiteralNode):
            if node.is_expandable:
                expanded = self._expand_string(node.value)
                return StringLiteralNode(value=expanded, is_expandable=True)
            return node
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        elif isinstance(node, TypeCastNode):
            return TypeCastNode(type_name=node.type_name, expression=self.visit(node.expression))
        elif isinstance(node, StaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)
        elif isinstance(node, RangeExpressionNode):
            return RangeExpressionNode(start=self.visit(node.start), end=self.visit(node.end))
        return node

    def visit_script_block(self, node: ScriptBlockNode) -> ScriptBlockNode:
        norm_statements = []
        for stmt in node.statements:
            norm_statements.append(self.visit(stmt))
        return ScriptBlockNode(statements=norm_statements)

    def visit_pipeline(self, node: PipelineNode) -> PipelineNode:
        return PipelineNode(elements=[self.visit(e) for e in node.elements])

    def visit_command(self, node: CommandNode) -> ASTNode:
        norm_target = self.visit(node.target)
        norm_args = [self.visit(a) for a in node.arguments]

        # Call operator simplification: & 'iex' 'payload' -> iex 'payload'
        if isinstance(norm_target, IdentifierNode) and norm_target.name in ("&", "."):
            if norm_args:
                first_arg = norm_args[0]
                inner_arg = first_arg.expression if isinstance(first_arg, ParenthesizedExpressionNode) else first_arg
                if isinstance(inner_arg, StringLiteralNode):
                    cmd_val = inner_arg.value.strip()
                    if re.match(r"^[A-Za-z0-9_.-]+$", cmd_val):
                        return CommandNode(
                            target=IdentifierNode(name=cmd_val),
                            arguments=norm_args[1:],
                        )
                elif isinstance(inner_arg, ScriptBlockNode) and len(norm_args) == 1:
                    if len(inner_arg.statements) == 1:
                        return inner_arg.statements[0]
                    return inner_arg

        return CommandNode(target=norm_target, arguments=norm_args)

    def visit_parenthesized(self, node: ParenthesizedExpressionNode) -> ASTNode:
        norm_inner = self.visit(node.expression)
        return ParenthesizedExpressionNode(expression=norm_inner)

    def visit_assignment(self, node: AssignmentNode) -> AssignmentNode:
        norm_expr = self.visit(node.expression)

        # Track environment variable assignments: $env:VAR = 'val'
        if node.variable.scope and node.variable.scope.lower() == "env":
            if isinstance(norm_expr, StringLiteralNode):
                self.env_vars[node.variable.name.upper()] = norm_expr.value
            elif isinstance(norm_expr, NumberLiteralNode):
                self.env_vars[node.variable.name.upper()] = str(norm_expr.value)
        # Track local / script / global variable assignments: $var = 'val'
        elif node.variable.scope is None or node.variable.scope.lower() in ("variable", "script", "global", "local"):
            var_key = node.variable.name.lower()
            if isinstance(norm_expr, StringLiteralNode):
                self.symbols[var_key] = norm_expr.value
            elif isinstance(norm_expr, NumberLiteralNode):
                self.symbols[var_key] = norm_expr.value
            else:
                self.symbols.pop(var_key, None)

        return AssignmentNode(variable=node.variable, expression=norm_expr)

    def visit_variable(self, node: VariableNode) -> ASTNode:
        scope = node.scope
        name = node.name
        if scope is None and ":" in name:
            parts = name.split(":", 1)
            scope = parts[0]
            name = parts[1]

        # 1. Environment variable inlining: $env:VAR
        if scope and scope.lower() == "env":
            var_key = name.upper()
            if var_key in self.env_vars:
                return StringLiteralNode(value=self.env_vars[var_key], is_expandable=False)
            return node

        # 2. Special / automatic variable inlining: $PSHOME, $ShellId, $ExecutionContext, $VerbosePreference
        if scope is None or scope.lower() in ("variable", "script", "global", "local"):
            var_upper = name.upper()
            if var_upper in self.special_vars:
                return StringLiteralNode(value=self.special_vars[var_upper], is_expandable=False)

            # 3. Constant propagation from symbol table: $var
            var_lower = name.lower()
            if var_lower in self.symbols:
                val = self.symbols[var_lower]
                if isinstance(val, str):
                    return StringLiteralNode(value=val, is_expandable=False)
                elif isinstance(val, (int, float)):
                    return NumberLiteralNode(value=val, raw=str(val))

        return node

    def visit_member_access(self, node: MemberAccessNode) -> ASTNode:
        target = self.visit(node.target)
        inner_target = target.expression if isinstance(target, ParenthesizedExpressionNode) else target
        member_name = node.member.strip('`"\'').lower()

        # $ExecutionContext properties
        if self._is_execution_context(inner_target):
            if member_name == "invokecommand":
                return StringLiteralNode(
                    value="System.Management.Automation.CommandInvocationIntrinsics",
                    is_expandable=False,
                )
            elif member_name == "sessionstate":
                return StringLiteralNode(
                    value="System.Management.Automation.SessionState",
                    is_expandable=False,
                )
            elif member_name == "host":
                return StringLiteralNode(
                    value="System.Management.Automation.Internal.Host.InternalHost",
                    is_expandable=False,
                )
            elif member_name == "invokeprovider":
                return StringLiteralNode(
                    value="System.Management.Automation.ProviderIntrinsics",
                    is_expandable=False,
                )

        # $ExecutionContext.SessionState properties
        if self._is_session_state(inner_target):
            if member_name == "invokecommand":
                return StringLiteralNode(
                    value="System.Management.Automation.CommandInvocationIntrinsics",
                    is_expandable=False,
                )
            elif member_name == "languagemode":
                return StringLiteralNode(
                    value="FullLanguage",
                    is_expandable=False,
                )
            elif member_name == "path":
                return StringLiteralNode(
                    value="System.Management.Automation.PathIntrinsics",
                    is_expandable=False,
                )

        # String properties
        if isinstance(inner_target, StringLiteralNode):
            if member_name == "length":
                return NumberLiteralNode(value=len(inner_target.value), raw=str(len(inner_target.value)))

        return MemberAccessNode(target=target, member=node.member)

    def visit_method_call(self, node: MethodCallNode) -> ASTNode:
        target = self.visit(node.target)
        norm_args = [self.visit(a) for a in node.arguments]
        inner_target = target.expression if isinstance(target, ParenthesizedExpressionNode) else target
        method_name = node.method_name.strip('`"\'').lower()

        # 1. $ExecutionContext.InvokeCommand methods
        if self._is_invoke_command(inner_target):
            if method_name == "invokescript" and norm_args:
                script_arg = norm_args[0]
                if isinstance(script_arg, StringLiteralNode):
                    try:
                        lexer = PowerShellLexer(script_arg.value)
                        parser = PowerShellParser(lexer.tokenize())
                        inner_ast = parser.parse()
                        if len(inner_ast.statements) == 1:
                            return inner_ast.statements[0]
                        elif len(inner_ast.statements) > 1:
                            return inner_ast
                    except Exception:
                        pass
                return CommandNode(
                    target=IdentifierNode(name="Invoke-Expression"),
                    arguments=[script_arg],
                )
            elif method_name == "newscriptblock" and norm_args:
                script_arg = norm_args[0]
                if isinstance(script_arg, StringLiteralNode):
                    try:
                        lexer = PowerShellLexer(script_arg.value)
                        parser = PowerShellParser(lexer.tokenize())
                        return parser.parse()
                    except Exception:
                        pass
                return ParenthesizedExpressionNode(expression=script_arg)
            elif method_name == "expandstring" and norm_args:
                script_arg = norm_args[0]
                if isinstance(script_arg, StringLiteralNode):
                    expanded = self._expand_string(script_arg.value)
                    return StringLiteralNode(value=expanded, is_expandable=False)
                return script_arg
            elif method_name in ("getcommand", "getcmdlet") and norm_args:
                cmd_arg = norm_args[0]
                if isinstance(cmd_arg, StringLiteralNode):
                    cmd_val = cmd_arg.value
                    if cmd_val.lower() == "iex":
                        return StringLiteralNode(value="Invoke-Expression", is_expandable=False)
                    return StringLiteralNode(value=cmd_val, is_expandable=False)
            elif method_name == "tostring":
                return StringLiteralNode(
                    value="System.Management.Automation.CommandInvocationIntrinsics",
                    is_expandable=False,
                )

        # 2. $ExecutionContext root methods
        if self._is_execution_context(inner_target):
            if method_name == "tostring":
                return StringLiteralNode(
                    value="System.Management.Automation.EngineIntrinsics",
                    is_expandable=False,
                )

        # 3. .Invoke() on ScriptBlockNode
        if method_name == "invoke":
            if isinstance(inner_target, ScriptBlockNode):
                if len(inner_target.statements) == 1:
                    return inner_target.statements[0]
                return inner_target
            elif isinstance(inner_target, ParenthesizedExpressionNode) and isinstance(inner_target.expression, (CommandNode, ScriptBlockNode)):
                return inner_target.expression

        # 4. String methods on StringLiteralNode
        if isinstance(inner_target, StringLiteralNode):
            s = inner_target.value
            if method_name == "tostring":
                return inner_target
            elif method_name in ("tolower", "tolowerinvariant"):
                return StringLiteralNode(value=s.lower(), is_expandable=False)
            elif method_name in ("toupper", "toupperinvariant"):
                return StringLiteralNode(value=s.upper(), is_expandable=False)
            elif method_name == "trim":
                return StringLiteralNode(value=s.strip(), is_expandable=False)
            elif method_name == "trimstart":
                return StringLiteralNode(value=s.lstrip(), is_expandable=False)
            elif method_name == "trimend":
                return StringLiteralNode(value=s.rstrip(), is_expandable=False)
            elif method_name == "substring" and norm_args:
                try:
                    start_val = self._extract_int(norm_args[0])
                    if start_val is not None and 0 <= start_val <= len(s):
                        if len(norm_args) >= 2:
                            len_val = self._extract_int(norm_args[1])
                            if len_val is not None:
                                sub = s[start_val:start_val + len_val]
                            else:
                                sub = s[start_val:]
                        else:
                            sub = s[start_val:]
                        return StringLiteralNode(value=sub, is_expandable=False)
                except Exception:
                    pass
            elif method_name == "replace" and len(norm_args) >= 2:
                if isinstance(norm_args[0], StringLiteralNode) and isinstance(norm_args[1], StringLiteralNode):
                    return StringLiteralNode(value=s.replace(norm_args[0].value, norm_args[1].value), is_expandable=False)
            elif method_name == "split" and len(norm_args) >= 1:
                if isinstance(norm_args[0], StringLiteralNode):
                    parts = s.split(norm_args[0].value)
                    return ArrayLiteralNode(elements=[StringLiteralNode(value=p, is_expandable=False) for p in parts])

        return MethodCallNode(target=target, method_name=node.method_name, arguments=norm_args)

    def visit_index_access(self, node: IndexAccessNode) -> ASTNode:
        target = self.visit(node.target)
        index = self.visit(node.index)
        inner_target = target.expression if isinstance(target, ParenthesizedExpressionNode) else target

        # Indexing into inlined StringLiteralNode
        if isinstance(inner_target, StringLiteralNode):
            indices = self._extract_indices(index)
            if indices is not None:
                s = inner_target.value
                n = len(s)
                if len(indices) == 1 and not isinstance(index, (ArrayLiteralNode, RangeExpressionNode)):
                    idx = indices[0]
                    if -n <= idx < n:
                        return StringLiteralNode(value=s[idx], is_expandable=False)
                extracted = []
                for idx in indices:
                    if -n <= idx < n:
                        extracted.append(StringLiteralNode(value=s[idx], is_expandable=False))
                return ArrayLiteralNode(elements=extracted)

        return IndexAccessNode(target=target, index=index)

    def visit_unary_op(self, node: UnaryOpNode) -> ASTNode:
        operand = self.visit(node.operand)
        if node.operator.lower() == "-join":
            inner = operand.expression if isinstance(operand, ParenthesizedExpressionNode) else operand
            if isinstance(inner, ArrayLiteralNode):
                if all(isinstance(e, StringLiteralNode) for e in inner.elements):
                    return StringLiteralNode(value="".join(e.value for e in inner.elements), is_expandable=False)
            elif isinstance(inner, StringLiteralNode):
                return inner
        return UnaryOpNode(operator=node.operator, operand=operand)

    def visit_binary_op(self, node: BinaryOpNode) -> ASTNode:
        left = self.visit(node.left)
        right = self.visit(node.right)
        if node.operator.lower() == "-join":
            inner_left = left.expression if isinstance(left, ParenthesizedExpressionNode) else left
            delim = right.value if isinstance(right, StringLiteralNode) else ""
            if isinstance(inner_left, ArrayLiteralNode):
                if all(isinstance(e, StringLiteralNode) for e in inner_left.elements):
                    return StringLiteralNode(value=delim.join(e.value for e in inner_left.elements), is_expandable=False)
            elif isinstance(inner_left, StringLiteralNode):
                return inner_left
        return BinaryOpNode(left=left, operator=node.operator, right=right)

    def visit_format_op(self, node: FormatOpNode) -> ASTNode:
        norm_fmt = self.visit(node.format_string)
        norm_args = [self.visit(a) for a in node.arguments]
        return FormatOpNode(format_string=norm_fmt, arguments=norm_args)

    def _is_execution_context(self, node: ASTNode) -> bool:
        if isinstance(node, VariableNode) and node.name.lower() == "executioncontext":
            return True
        if isinstance(node, StringLiteralNode) and node.value == "System.Management.Automation.EngineIntrinsics":
            return True
        return False

    def _is_invoke_command(self, node: ASTNode) -> bool:
        if isinstance(node, MemberAccessNode):
            target = node.target.expression if isinstance(node.target, ParenthesizedExpressionNode) else node.target
            if self._is_execution_context(target) and node.member.strip('`"\'').lower() == "invokecommand":
                return True
        if isinstance(node, StringLiteralNode) and node.value == "System.Management.Automation.CommandInvocationIntrinsics":
            return True
        return False

    def _is_session_state(self, node: ASTNode) -> bool:
        if isinstance(node, MemberAccessNode):
            target = node.target.expression if isinstance(node.target, ParenthesizedExpressionNode) else node.target
            if self._is_execution_context(target) and node.member.strip('`"\'').lower() == "sessionstate":
                return True
        if isinstance(node, StringLiteralNode) and node.value == "System.Management.Automation.SessionState":
            return True
        return False

    def _expand_string(self, text: str) -> str:
        def replace_env(m: re.Match) -> str:
            var_name = m.group(1).upper()
            return self.env_vars.get(var_name, m.group(0))

        text = re.sub(r"\$\{env:([A-Za-z0-9_()]+)\}", replace_env, text, flags=re.IGNORECASE)
        text = re.sub(r"\$env:([A-Za-z0-9_]+(?:\([A-Za-z0-9_]+\))?)", replace_env, text, flags=re.IGNORECASE)

        def replace_special(m: re.Match) -> str:
            var_name = m.group(1).upper()
            if var_name in self.special_vars:
                return self.special_vars[var_name]
            var_lower = m.group(1).lower()
            if var_lower in self.symbols and isinstance(self.symbols[var_lower], (str, int, float)):
                return str(self.symbols[var_lower])
            return m.group(0)

        text = re.sub(r"\$\{([A-Za-z0-9_]+)\}", replace_special, text)
        text = re.sub(r"\$([A-Za-z0-9_]+)", replace_special, text)
        return text

    def _extract_indices(self, node: ASTNode) -> Optional[List[int]]:
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_indices(node.expression)
        if isinstance(node, NumberLiteralNode):
            try:
                return [int(node.value)]
            except ValueError:
                return None
        if isinstance(node, RangeExpressionNode):
            start_list = self._extract_indices(node.start)
            end_list = self._extract_indices(node.end)
            if start_list and end_list and len(start_list) == 1 and len(end_list) == 1:
                s, e = start_list[0], end_list[0]
                step = 1 if s <= e else -1
                return list(range(s, e + step, step))
            return None
        if isinstance(node, ArrayLiteralNode):
            res = []
            for e in node.elements:
                sub = self._extract_indices(e)
                if sub is None:
                    return None
                res.extend(sub)
            return res
        return None

    def _extract_int(self, node: ASTNode) -> Optional[int]:
        if isinstance(node, NumberLiteralNode):
            try:
                return int(node.value)
            except ValueError:
                return None
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_int(node.expression)
        return None
