"""
PowerShell Casing Randomization Normalizer.
Canonicalizes identifiers, cmdlet names, keywords, type accelerators, member methods,
CLI parameters, and environment/automatic variables to standard PowerShell and .NET conventions.
"""

import re
from typing import Any, Dict, List, Optional, Set

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


class PowerShellCasingNormalizer:
    """
    AST Visitor normalizing randomized casing evasion techniques in obfuscated scripts.
    Restores canonical casing for cmdlets, keywords, types, members, parameters, and variables.
    """

    APPROVED_VERBS: Set[str] = {
        "Get", "Set", "New", "Remove", "Invoke", "Start", "Stop",
        "Convert", "ConvertTo", "ConvertFrom", "Out", "Write", "Add",
        "Clear", "Test", "Select", "Where", "ForEach", "Sort", "Group",
        "Measure", "Compare", "Export", "Import", "Enable", "Disable",
        "Install", "Uninstall", "Update", "Find", "Show", "Hide",
        "Wait", "Read", "Push", "Pop", "Resume", "Suspend", "Restart",
        "Reset", "Step", "Split", "Join", "Merge", "Switch",
    }

    VERBS_MAP: Dict[str, str] = {v.lower(): v for v in APPROVED_VERBS}

    KNOWN_CMDLETS: Dict[str, str] = {
        "invoke-expression": "Invoke-Expression",
        "iex": "iex",
        "get-command": "Get-Command",
        "gcm": "Get-Command",
        "get-item": "Get-Item",
        "gi": "Get-Item",
        "get-childitem": "Get-ChildItem",
        "gci": "Get-ChildItem",
        "dir": "Get-ChildItem",
        "ls": "Get-ChildItem",
        "new-object": "New-Object",
        "start-process": "Start-Process",
        "saps": "Start-Process",
        "stop-process": "Stop-Process",
        "kill": "Stop-Process",
        "invoke-webrequest": "Invoke-WebRequest",
        "iwr": "Invoke-WebRequest",
        "invoke-restmethod": "Invoke-RestMethod",
        "irm": "Invoke-RestMethod",
        "convertto-securestring": "ConvertTo-SecureString",
        "convertfrom-securestring": "ConvertFrom-SecureString",
        "set-executionpolicy": "Set-ExecutionPolicy",
        "get-executionpolicy": "Get-ExecutionPolicy",
        "write-host": "Write-Host",
        "write-output": "Write-Output",
        "echo": "Write-Output",
        "out-string": "Out-String",
        "out-null": "Out-Null",
        "out-file": "Out-File",
        "foreach-object": "ForEach-Object",
        "%": "%",
        "where-object": "Where-Object",
        "?": "?",
        "select-object": "Select-Object",
        "select": "Select-Object",
        "add-type": "Add-Type",
        "set-content": "Set-Content",
        "get-content": "Get-Content",
        "cat": "Get-Content",
        "type": "Get-Content",
    }

    KEYWORDS: Set[str] = {
        "if", "else", "elseif", "foreach", "for", "while", "do", "until",
        "break", "continue", "return", "function", "filter", "param",
        "try", "catch", "finally", "throw", "trap", "class", "enum",
        "using", "in",
    }

    KNOWN_TYPES: Dict[str, str] = {
        "system.net.webclient": "System.Net.WebClient",
        "system.text.encoding": "System.Text.Encoding",
        "system.convert": "System.Convert",
        "system.io.memorystream": "System.IO.MemoryStream",
        "system.io.compression.gzipstream": "System.IO.Compression.GZipStream",
        "system.io.compression.deflatestream": "System.IO.Compression.DeflateStream",
        "system.runtime.interopservices.marshal": "System.Runtime.InteropServices.Marshal",
        "system.diagnostics.process": "System.Diagnostics.Process",
        "system.math": "System.Math",
        "system.environment": "System.Environment",
        "system.io.file": "System.IO.File",
        "system.reflection.assembly": "System.Reflection.Assembly",
        "byte[]": "byte[]",
        "char[]": "char[]",
        "string": "string",
        "int": "int",
        "int32": "int32",
        "int64": "int64",
        "long": "long",
        "bool": "bool",
        "boolean": "boolean",
        "type": "type",
        "regex": "regex",
        "char": "char",
        "byte": "byte",
        "string[]": "string[]",
        "int[]": "int[]",
    }

    KNOWN_MEMBERS: Dict[str, str] = {
        "downloadstring": "DownloadString",
        "downloaddata": "DownloadData",
        "downloadfile": "DownloadFile",
        "uploadstring": "UploadString",
        "uploaddata": "UploadData",
        "getstring": "GetString",
        "getbytes": "GetBytes",
        "frombase64string": "FromBase64String",
        "tobase64string": "ToBase64String",
        "substring": "Substring",
        "toupper": "ToUpper",
        "tolower": "ToLower",
        "trim": "Trim",
        "trimstart": "TrimStart",
        "trimend": "TrimEnd",
        "replace": "Replace",
        "split": "Split",
        "contains": "Contains",
        "startswith": "StartsWith",
        "endswith": "EndsWith",
        "indexof": "IndexOf",
        "invoke": "Invoke",
        "getmethod": "GetMethod",
        "getproperty": "GetProperty",
        "getfield": "GetField",
        "gettype": "GetType",
        "length": "Length",
        "count": "Count",
        "readalltext": "ReadAllText",
        "writealltext": "WriteAllText",
    }

    KNOWN_CLI_FLAGS: Dict[str, str] = {
        "-encodedcommand": "-EncodedCommand",
        "-noprofile": "-NoProfile",
        "-noninteractive": "-NonInteractive",
        "-windowstyle": "-WindowStyle",
        "-executionpolicy": "-ExecutionPolicy",
        "-command": "-Command",
        "-file": "-File",
        "-sta": "-Sta",
        "-version": "-Version",
    }

    KNOWN_AUTO_VARS: Dict[str, str] = {
        "true": "true",
        "false": "false",
        "null": "null",
        "pshome": "PSHOME",
        "shellid": "ShellId",
        "verbosepreference": "VerbosePreference",
    }

    KNOWN_ENV_VARS: Dict[str, str] = {
        "comspec": "COMSPEC",
        "systemroot": "SystemRoot",
        "path": "PATH",
        "temp": "TEMP",
        "tmp": "TEMP",
        "userprofile": "USERPROFILE",
        "programfiles": "ProgramFiles",
        "windir": "windir",
    }

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols = symbols if symbols is not None else {}

    def normalize(self, node: ASTNode) -> ASTNode:
        """Entry point for casing normalization traversal."""
        return self.visit(node)

    def visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, CommandNode):
            return self.visit_command(node)
        elif isinstance(node, AssignmentNode):
            return self.visit_assignment(node)
        elif isinstance(node, IdentifierNode):
            return self.visit_identifier(node)
        elif isinstance(node, VariableNode):
            return self.visit_variable(node)
        elif isinstance(node, MemberAccessNode):
            return self.visit_member_access(node)
        elif isinstance(node, MethodCallNode):
            return self.visit_method_call(node)
        elif isinstance(node, StaticMemberAccessNode):
            return self.visit_static_member(node)
        elif isinstance(node, DynamicMemberAccessNode):
            return self.visit_dynamic_member_access(node)
        elif isinstance(node, DynamicMethodCallNode):
            return self.visit_dynamic_method_call(node)
        elif isinstance(node, DynamicStaticMemberAccessNode):
            return self.visit_dynamic_static_member(node)
        elif isinstance(node, TypeCastNode):
            return self.visit_type_cast(node)
        elif isinstance(node, SubexpressionNode):
            return self.visit_subexpression(node)
        elif isinstance(node, ParenthesizedExpressionNode):
            return ParenthesizedExpressionNode(expression=self.visit(node.expression))
        elif isinstance(node, BinaryOpNode):
            return BinaryOpNode(left=self.visit(node.left), operator=node.operator, right=self.visit(node.right))
        elif isinstance(node, UnaryOpNode):
            return UnaryOpNode(operator=node.operator, operand=self.visit(node.operand))
        elif isinstance(node, FormatOpNode):
            return FormatOpNode(
                format_string=self.visit(node.format_string),
                arguments=[self.visit(a) for a in node.arguments],
            )
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        elif isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self.visit(node.target), index=self.visit(node.index))
        elif isinstance(node, RangeExpressionNode):
            return RangeExpressionNode(start=self.visit(node.start), end=self.visit(node.end))
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

    def visit_pipeline(self, node: PipelineNode) -> PipelineNode:
        return PipelineNode(elements=[self.visit(e) for e in node.elements])

    def visit_subexpression(self, node: SubexpressionNode) -> SubexpressionNode:
        return SubexpressionNode(statements=[self.visit(s) for s in node.statements])

    def visit_command(self, node: CommandNode) -> CommandNode:
        norm_target = self.visit(node.target)
        if isinstance(norm_target, IdentifierNode):
            norm_name = self._normalize_cmdlet_name(norm_target.name)
            norm_target = IdentifierNode(name=norm_name)
        elif isinstance(norm_target, StringLiteralNode):
            norm_name = self._normalize_cmdlet_name(norm_target.value)
            norm_target = StringLiteralNode(value=norm_name, is_expandable=norm_target.is_expandable)

        norm_args = [self.visit(a) for a in node.arguments]
        return CommandNode(target=norm_target, arguments=norm_args)

    def visit_assignment(self, node: AssignmentNode) -> AssignmentNode:
        norm_var = self.visit_variable(node.variable)
        norm_expr = self.visit(node.expression)
        return AssignmentNode(variable=norm_var, expression=norm_expr)

    def visit_identifier(self, node: IdentifierNode) -> IdentifierNode:
        name = node.name

        # Keyword normalization (e.g., iF -> if, fOrEaCh -> foreach)
        if name.lower() in self.KEYWORDS:
            return IdentifierNode(name=name.lower())

        # CLI flag normalization (e.g., -eNcOdEdCoMmAnD -> -EncodedCommand)
        if name.startswith("-"):
            norm_flag = self.KNOWN_CLI_FLAGS.get(name.lower())
            if norm_flag:
                return IdentifierNode(name=norm_flag)
            return node

        # Type literal in brackets (e.g., [bYtE[]] -> [byte[]])
        if name.startswith("[") and name.endswith("]"):
            inner = name[1:-1]
            norm_type = self._normalize_type_name(inner)
            return IdentifierNode(name=f"[{norm_type}]")

        # Known type without brackets (e.g., System.Net.WebClient)
        if name.lower() in self.KNOWN_TYPES:
            return IdentifierNode(name=self.KNOWN_TYPES[name.lower()])

        # Cmdlet or verb-noun normalization
        norm_cmd = self._normalize_cmdlet_name(name)
        if norm_cmd != name:
            return IdentifierNode(name=norm_cmd)

        return node

    def visit_variable(self, node: VariableNode) -> VariableNode:
        scope = node.scope
        name = node.name

        # Check composite $env:NAME in name without scope
        if scope is None and ":" in name:
            parts = name.split(":", 1)
            scope = parts[0]
            name = parts[1]

        # Environment variable casing (e.g., $eNv:CoMsPeC -> $env:COMSPEC)
        if scope and scope.lower() == "env":
            norm_env = self.KNOWN_ENV_VARS.get(name.lower(), name.upper())
            return VariableNode(name=norm_env, scope="env")

        # Automatic variables ($true, $false, $null, $PSHOME, etc.)
        var_low = name.lower()
        if var_low in self.KNOWN_AUTO_VARS:
            return VariableNode(name=self.KNOWN_AUTO_VARS[var_low], scope=scope)

        return VariableNode(name=name, scope=scope)

    def visit_member_access(self, node: MemberAccessNode) -> ASTNode:
        dotted = self._extract_dotted_name(node)
        if dotted and dotted.lower() in self.KNOWN_TYPES:
            return IdentifierNode(name=self.KNOWN_TYPES[dotted.lower()])

        norm_target = self.visit(node.target)
        norm_member = self.KNOWN_MEMBERS.get(node.member.lower(), node.member)
        return MemberAccessNode(target=norm_target, member=norm_member)

    def _extract_dotted_name(self, node: ASTNode) -> Optional[str]:
        """Extracts complete dotted chain name if node is purely dotted identifiers."""
        if isinstance(node, IdentifierNode):
            return node.name
        if isinstance(node, MemberAccessNode):
            parent = self._extract_dotted_name(node.target)
            if parent is not None:
                return f"{parent}.{node.member}"
        return None

    def visit_method_call(self, node: MethodCallNode) -> MethodCallNode:
        norm_target = self.visit(node.target)
        norm_method = self.KNOWN_MEMBERS.get(node.method_name.lower(), node.method_name)
        norm_args = [self.visit(a) for a in node.arguments]
        return MethodCallNode(target=norm_target, method_name=norm_method, arguments=norm_args)

    def visit_static_member(self, node: StaticMemberAccessNode) -> StaticMemberAccessNode:
        norm_type = self._normalize_type_name(node.type_name)
        norm_member = self.KNOWN_MEMBERS.get(node.member.lower(), node.member)
        norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
        return StaticMemberAccessNode(type_name=norm_type, member=norm_member, arguments=norm_args)

    def visit_dynamic_member_access(self, node: DynamicMemberAccessNode) -> ASTNode:
        norm_target = self.visit(node.target)
        norm_expr = self.visit(node.member_expr)
        if isinstance(norm_expr, StringLiteralNode):
            norm_member = self.KNOWN_MEMBERS.get(norm_expr.value.lower(), norm_expr.value)
            return MemberAccessNode(target=norm_target, member=norm_member)
        return DynamicMemberAccessNode(target=norm_target, member_expr=norm_expr)

    def visit_dynamic_method_call(self, node: DynamicMethodCallNode) -> ASTNode:
        norm_target = self.visit(node.target)
        norm_expr = self.visit(node.member_expr)
        norm_args = [self.visit(a) for a in node.arguments]
        if isinstance(norm_expr, StringLiteralNode):
            norm_method = self.KNOWN_MEMBERS.get(norm_expr.value.lower(), norm_expr.value)
            return MethodCallNode(target=norm_target, method_name=norm_method, arguments=norm_args)
        return DynamicMethodCallNode(target=norm_target, method_expr=norm_expr, arguments=norm_args)

    def visit_dynamic_static_member(self, node: DynamicStaticMemberAccessNode) -> ASTNode:
        norm_type = self._normalize_type_name(node.type_name)
        norm_expr = self.visit(node.member_expr)
        norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
        if isinstance(norm_expr, StringLiteralNode):
            norm_member = self.KNOWN_MEMBERS.get(norm_expr.value.lower(), norm_expr.value)
            return StaticMemberAccessNode(type_name=norm_type, member=norm_member, arguments=norm_args)
        return DynamicStaticMemberAccessNode(type_name=norm_type, member_expr=norm_expr, arguments=norm_args)

    def visit_type_cast(self, node: TypeCastNode) -> TypeCastNode:
        norm_type = self._normalize_type_name(node.type_name)
        norm_expr = self.visit(node.expression)
        return TypeCastNode(type_name=norm_type, expression=norm_expr)

    def _normalize_cmdlet_name(self, name: str) -> str:
        """Normalizes cmdlet and alias names, including approved Verb-Noun patterns."""
        low = name.lower()
        if low in self.KNOWN_CMDLETS:
            return self.KNOWN_CMDLETS[low]

        if "-" in name:
            parts = name.split("-", 1)
            verb_low = parts[0].lower()
            if verb_low in self.VERBS_MAP:
                canonical_verb = self.VERBS_MAP[verb_low]
                noun_part = parts[1]
                canonical_noun = noun_part.capitalize()
                return f"{canonical_verb}-{canonical_noun}"

        return name

    def _normalize_type_name(self, type_name: str) -> str:
        """Normalizes .NET type and type accelerator names (with or without brackets)."""
        clean = type_name.strip()
        if clean.startswith("[") and clean.endswith("]"):
            clean = clean[1:-1]

        clean_low = clean.lower()
        if clean_low in self.KNOWN_TYPES:
            return self.KNOWN_TYPES[clean_low]

        # Handle array types like System.Byte[]
        if clean_low.endswith("[]"):
            base_type = clean[:-2]
            norm_base = self._normalize_type_name(base_type)
            return f"{norm_base}[]"

        return clean
