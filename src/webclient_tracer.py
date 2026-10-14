"""
PowerShell DownloadString & WebClient API Static Tracer and URL Carver.
Performs compiler-grade AST analysis and static extraction of remote payload URLs,
download cradles, headers, proxy configurations, and obfuscated IP formats.
"""

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

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
    IndexAccessNode,
    MemberAccessNode,
    MethodCallNode,
    NumberLiteralNode,
    ParenthesizedExpressionNode,
    PipelineNode,
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
from .url_target import (
    DOWNLOAD_CMDLETS,
    HTTPCLIENT_DOWNLOAD_METHODS,
    WEBCLIENT_DOWNLOAD_METHODS,
    RemotePayloadTarget,
    canonicalize_url,
    decode_host_ip,
    decode_ip_part,
)


class PowerShellWebClientTracer:
    """
    Compiler-grade AST static tracer for PowerShell WebClient calls, download cmdlets,
    and remote payload URL carving.
    """

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols: Dict[str, Any] = dict(symbols) if symbols is not None else {}
        self.headers_by_var: Dict[str, Dict[str, str]] = {}
        self.proxy_by_var: Dict[str, str] = {}

    def trace(self, node: ASTNode) -> List[RemotePayloadTarget]:
        """
        Traverses an AST structure and extracts all remote payload targets.
        """
        targets: List[RemotePayloadTarget] = []
        self._visit(node, parent=None, results=targets)
        return targets

    def carve_text(self, text: str) -> List[RemotePayloadTarget]:
        """
        Parses script text into an AST, extracts targets via AST traversal,
        and augments with regex heuristic carving for uncalled string literals.
        """
        targets: List[RemotePayloadTarget] = []
        seen_urls: Set[str] = set()

        try:
            tokens = PowerShellLexer(text).tokenize()
            ast = PowerShellParser(tokens).parse()
            ast_targets = self.trace(ast)
            for t in ast_targets:
                if t.url not in seen_urls:
                    seen_urls.add(t.url)
                    targets.append(t)
        except Exception:
            pass

        # Heuristic fallback carving across the entire text
        heuristic_targets = self._carve_regex_urls(text, exclude_urls=seen_urls)
        for t in heuristic_targets:
            if t.url not in seen_urls:
                seen_urls.add(t.url)
                targets.append(t)

        return targets

    def _visit(
        self,
        node: ASTNode,
        parent: Optional[ASTNode],
        results: List[RemotePayloadTarget]
    ) -> None:
        """Recursive AST visitor dispatching inspection hooks."""
        if node is None:
            return

        if isinstance(node, ScriptBlockNode):
            for stmt in node.statements:
                self._visit(stmt, parent=node, results=results)
        elif isinstance(node, PipelineNode):
            for stage in node.elements:
                self._visit(stage, parent=node, results=results)
        elif isinstance(node, AssignmentNode):
            self._inspect_assignment(node)
            self._visit(node.expression, parent=node, results=results)
        elif isinstance(node, StaticMemberAccessNode):
            self._inspect_static_member(node, parent=parent, results=results)
            if node.arguments:
                for arg in node.arguments:
                    self._visit(arg, parent=node, results=results)
        elif isinstance(node, MethodCallNode):
            self._inspect_method_call(node, parent=parent, results=results)
            self._visit(node.target, parent=node, results=results)
            for arg in node.arguments:
                self._visit(arg, parent=node, results=results)
        elif isinstance(node, DynamicMethodCallNode):
            self._inspect_dynamic_method_call(node, parent=parent, results=results)
            self._visit(node.target, parent=node, results=results)
            self._visit(node.method_expr, parent=node, results=results)
            for arg in node.arguments:
                self._visit(arg, parent=node, results=results)
        elif isinstance(node, CommandNode):
            self._inspect_command(node, parent=parent, results=results)
            self._visit(node.target, parent=node, results=results)
            for arg in node.arguments:
                self._visit(arg, parent=node, results=results)
        elif isinstance(node, ParenthesizedExpressionNode):
            self._visit(node.expression, parent=node, results=results)
        elif isinstance(node, SubexpressionNode):
            for stmt in node.statements:
                self._visit(stmt, parent=node, results=results)
        elif isinstance(node, BinaryOpNode):
            self._visit(node.left, parent=node, results=results)
            self._visit(node.right, parent=node, results=results)
        elif isinstance(node, FormatOpNode):
            self._visit(node.format_string, parent=node, results=results)
            arg_nodes = node.arguments.elements if isinstance(node.arguments, ArrayLiteralNode) else node.arguments
            for arg in arg_nodes:
                self._visit(arg, parent=node, results=results)
        elif isinstance(node, ArrayLiteralNode):
            for elem in node.elements:
                self._visit(elem, parent=node, results=results)
        elif isinstance(node, TypeCastNode):
            self._visit(node.expression, parent=node, results=results)
        elif isinstance(node, UnaryOpNode):
            self._visit(node.operand, parent=node, results=results)
        elif isinstance(node, IndexAccessNode):
            self._visit(node.target, parent=node, results=results)
            self._visit(node.index, parent=node, results=results)

    def _inspect_assignment(self, node: AssignmentNode) -> None:
        """Tracks variable assignments ($u = 'http://...', $wc.Headers.Add(...))."""
        var_name = ""
        if isinstance(node.variable, VariableNode):
            var_name = node.variable.name.lower()
        elif isinstance(node.variable, IdentifierNode):
            var_name = node.variable.name.lstrip("$").lower()

        # Check for scalar string / URL assignment
        str_val = self._resolve_string_expr(node.expression)
        if var_name and str_val is not None:
            self.symbols[var_name] = str_val

        # Check for Headers assignment: $wc.Headers['User-Agent'] = 'Mozilla/5.0'
        if isinstance(node.variable, IndexAccessNode):
            target = node.variable.target
            if isinstance(target, MemberAccessNode) and target.member.lower() == "headers":
                if isinstance(target.target, VariableNode):
                    wc_var = target.target.name.lower()
                    hdr_key = str(self._resolve_string_expr(node.variable.index) or "")
                    hdr_val = str(self._resolve_string_expr(node.expression) or "")
                    if hdr_key and hdr_val:
                        self.headers_by_var.setdefault(wc_var, {})[hdr_key] = hdr_val

        # Check for Proxy assignment: $wc.Proxy = ...
        if isinstance(node.variable, MemberAccessNode) and node.variable.member.lower() == "proxy":
            if isinstance(node.variable.target, VariableNode):
                wc_var = node.variable.target.name.lower()
                proxy_val = self._resolve_string_expr(node.expression) or "custom_proxy"
                self.proxy_by_var[wc_var] = proxy_val

    def _inspect_static_member(
        self,
        node: StaticMemberAccessNode,
        parent: Optional[ASTNode],
        results: List[RemotePayloadTarget]
    ) -> None:
        """Inspects [System.Net.WebRequest]::Create('http://...')"""
        m_name = node.member.lower()
        if m_name == "create" and "webrequest" in node.type_name.lower():
            if node.arguments:
                raw_url_val = self._resolve_string_expr(node.arguments[0])
                if raw_url_val:
                    canon_url, scheme, host, port, path, query, ip_dec, is_val = canonicalize_url(raw_url_val)
                    results.append(
                        RemotePayloadTarget(
                            url=canon_url,
                            raw_url=raw_url_val,
                            method="Create",
                            api_type="WebRequest",
                            destination_file=None,
                            headers={},
                            cradle_type="generic_download",
                            scheme=scheme,
                            host=host,
                            port=port,
                            path=path,
                            query=query,
                            ip_decoded=ip_dec,
                            is_valid_url=is_val,
                            confidence=1.0,
                        )
                    )

    def _inspect_method_call(
        self,
        node: MethodCallNode,
        parent: Optional[ASTNode],
        results: List[RemotePayloadTarget]
    ) -> None:
        """Inspects .MethodCallNode for WebClient, HttpClient, and WebRequest methods."""
        m_name = node.method_name.lower()

        # Track $wc.Headers.Add('Header', 'Value')
        if m_name == "add" and isinstance(node.target, MemberAccessNode):
            if node.target.member.lower() == "headers" and isinstance(node.target.target, VariableNode):
                wc_var = node.target.target.name.lower()
                if len(node.arguments) >= 2:
                    k = self._resolve_string_expr(node.arguments[0])
                    v = self._resolve_string_expr(node.arguments[1])
                    if k and v:
                        self.headers_by_var.setdefault(wc_var, {})[k] = v
                return

        # Check WebClient methods
        if m_name in WEBCLIENT_DOWNLOAD_METHODS:
            self._record_method_target(
                node=node,
                parent=parent,
                method_name=node.method_name,
                api_type="WebClient",
                results=results,
            )
            return

        # Check HttpClient methods
        if m_name in HTTPCLIENT_DOWNLOAD_METHODS:
            self._record_method_target(
                node=node,
                parent=parent,
                method_name=node.method_name,
                api_type="HttpClient",
                results=results,
            )
            return

    def _inspect_dynamic_method_call(
        self,
        node: DynamicMethodCallNode,
        parent: Optional[ASTNode],
        results: List[RemotePayloadTarget]
    ) -> None:
        """Inspects .('Down'+'loadString') dynamic method calls."""
        resolved_m_name = self._resolve_string_expr(node.method_expr)
        if not resolved_m_name:
            return

        m_name = resolved_m_name.lower()
        if m_name in WEBCLIENT_DOWNLOAD_METHODS:
            self._record_method_target(
                node=node,
                parent=parent,
                method_name=resolved_m_name,
                api_type="WebClient",
                results=results,
            )
        elif m_name in HTTPCLIENT_DOWNLOAD_METHODS:
            self._record_method_target(
                node=node,
                parent=parent,
                method_name=resolved_m_name,
                api_type="HttpClient",
                results=results,
            )

    def _inspect_command(
        self,
        node: CommandNode,
        parent: Optional[ASTNode],
        results: List[RemotePayloadTarget]
    ) -> None:
        """Inspects cmdlet calls such as Invoke-WebRequest, Invoke-RestMethod, Start-BitsTransfer."""
        cmd_name = ""
        if isinstance(node.target, IdentifierNode):
            cmd_name = node.target.name.lower()
        elif isinstance(node.target, StringLiteralNode):
            cmd_name = node.target.value.lower()

        if cmd_name not in DOWNLOAD_CMDLETS:
            return

        # Extract arguments: positional or flags (-Uri, -OutFile, -Headers, etc.)
        url_arg: Optional[str] = None
        out_file_arg: Optional[str] = None
        user_agent_arg: Optional[str] = None
        headers_dict: Dict[str, str] = {}

        idx = 0
        while idx < len(node.arguments):
            arg = node.arguments[idx]
            arg_str = self._resolve_string_expr(arg)

            if isinstance(arg, IdentifierNode) and arg.name.startswith("-"):
                flag = arg.name.lower().lstrip("-")
                idx += 1
                if idx < len(node.arguments):
                    val_node = node.arguments[idx]
                    val_str = self._resolve_string_expr(val_node)
                    if flag in ("uri", "url", "source", "u"):
                        url_arg = val_str
                    elif flag in ("outfile", "out", "destination", "dest", "o"):
                        out_file_arg = val_str
                    elif flag in ("useragent", "ua"):
                        user_agent_arg = val_str
            else:
                # Positional argument: first positional string is typically Uri
                if url_arg is None and arg_str:
                    url_arg = arg_str
                elif out_file_arg is None and arg_str and cmd_name == "start-bitstransfer":
                    out_file_arg = arg_str
            idx += 1

        if url_arg:
            canon_url, scheme, host, port, path, query, ip_dec, is_val = canonicalize_url(url_arg)
            if user_agent_arg:
                headers_dict["User-Agent"] = user_agent_arg

            cradle_type = "cmdlet_download"
            if cmd_name == "start-bitstransfer":
                cradle_type = "bits_transfer"

            results.append(
                RemotePayloadTarget(
                    url=canon_url,
                    raw_url=url_arg,
                    method=cmd_name,
                    api_type="Cmdlet" if cmd_name != "start-bitstransfer" else "BitsTransfer",
                    destination_file=out_file_arg,
                    headers=headers_dict,
                    cradle_type=cradle_type,
                    scheme=scheme,
                    host=host,
                    port=port,
                    path=path,
                    query=query,
                    ip_decoded=ip_dec,
                    is_valid_url=is_val,
                    confidence=1.0,
                )
            )

    def _record_method_target(
        self,
        node: Union[MethodCallNode, DynamicMethodCallNode],
        parent: Optional[ASTNode],
        method_name: str,
        api_type: str,
        results: List[RemotePayloadTarget]
    ) -> None:
        """Extracts and normalizes arguments from a download method invocation."""
        if not node.arguments:
            return

        raw_url_val = self._resolve_string_expr(node.arguments[0])
        if not raw_url_val:
            return

        dest_file: Optional[str] = None
        if len(node.arguments) >= 2:
            dest_file = self._resolve_string_expr(node.arguments[1])

        # Retrieve headers and proxy bound to the target variable
        headers: Dict[str, str] = {}
        proxy: Optional[str] = None
        if isinstance(node.target, VariableNode):
            v_name = node.target.name.lower()
            headers = dict(self.headers_by_var.get(v_name, {}))
            proxy = self.proxy_by_var.get(v_name)

        cradle_type = self._determine_cradle_type(node, parent, method_name)
        canon_url, scheme, host, port, path, query, ip_dec, is_val = canonicalize_url(raw_url_val)

        results.append(
            RemotePayloadTarget(
                url=canon_url,
                raw_url=raw_url_val,
                method=method_name,
                api_type=api_type,
                destination_file=dest_file,
                headers=headers,
                proxy=proxy,
                cradle_type=cradle_type,
                scheme=scheme,
                host=host,
                port=port,
                path=path,
                query=query,
                ip_decoded=ip_dec,
                is_valid_url=is_val,
                confidence=1.0,
            )
        )

    def _determine_cradle_type(
        self,
        call_node: ASTNode,
        parent: Optional[ASTNode],
        method_name: str
    ) -> str:
        """Determines the forensic cradle execution pattern."""
        m_lower = method_name.lower()

        # 1. Piped into IEX or another command
        if isinstance(parent, PipelineNode):
            for stage in parent.elements:
                if isinstance(stage, CommandNode) and isinstance(stage.target, IdentifierNode):
                    if stage.target.name.lower() in ("iex", "invoke-expression"):
                        return "iex_download_string"

        # 2. Wrapped as argument in IEX (e.g. IEX (New-Object Net.WebClient).DownloadString(...))
        if isinstance(parent, CommandNode) and isinstance(parent.target, IdentifierNode):
            if parent.target.name.lower() in ("iex", "invoke-expression", "&", "."):
                return "iex_download_string"

        # 3. Passed into [Assembly]::Load(...)
        if isinstance(parent, StaticMemberAccessNode) and parent.member.lower() == "load":
            return "in_memory_assembly_load"
        if isinstance(parent, MethodCallNode) and parent.method_name.lower() == "load":
            return "in_memory_assembly_load"

        # 4. Method signature heuristics
        if m_lower == "downloadfile":
            return "file_download_execute"
        if m_lower == "downloaddata":
            return "in_memory_data"
        if m_lower == "downloadstring":
            return "iex_download_string"

        return "generic_download"

    def _resolve_string_expr(self, node: ASTNode) -> Optional[str]:
        """Statically resolves an AST node into a string value if constant."""
        if node is None:
            return None
        if isinstance(node, StringLiteralNode):
            return node.value
        if isinstance(node, NumberLiteralNode):
            return str(node.value)
        if isinstance(node, VariableNode):
            var_key = node.name.lower()
            if var_key in self.symbols:
                return str(self.symbols[var_key])
            return None
        if isinstance(node, ParenthesizedExpressionNode):
            return self._resolve_string_expr(node.expression)
        if isinstance(node, SubexpressionNode) and len(node.statements) == 1:
            return self._resolve_string_expr(node.statements[0])
        if isinstance(node, BinaryOpNode) and node.operator == "+":
            l_str = self._resolve_string_expr(node.left)
            r_str = self._resolve_string_expr(node.right)
            if l_str is not None and r_str is not None:
                return l_str + r_str
        if isinstance(node, FormatOpNode):
            fmt_str = self._resolve_string_expr(node.format_string)
            if fmt_str is not None:
                arg_nodes = node.arguments.elements if isinstance(node.arguments, ArrayLiteralNode) else node.arguments
                args = [self._resolve_string_expr(elem) for elem in arg_nodes]
                if all(a is not None for a in args):
                    try:
                        return re.sub(
                            r"\{([0-9]+)\}",
                            lambda m: args[int(m.group(1))] if int(m.group(1)) < len(args) else m.group(0),
                            fmt_str,
                        )
                    except Exception:
                        pass
        return None

    def _carve_regex_urls(
        self,
        text: str,
        exclude_urls: Optional[Set[str]] = None
    ) -> List[RemotePayloadTarget]:
        """
        Heuristic regex scanner identifying remote endpoint URLs embedded
        in raw text strings, comments, or uncalled arrays.
        """
        exclude = set(exclude_urls) if exclude_urls is not None else set()
        # Exclude configured proxy servers from payload download targets
        for p in self.proxy_by_var.values():
            exclude.add(p)
            try:
                p_canon, _, _, _, _, _, _, _ = canonicalize_url(p)
                exclude.add(p_canon)
            except Exception:
                pass

        results: List[RemotePayloadTarget] = []

        # Strictly bounded, linear-time regex pattern to prevent ReDoS
        pattern = re.compile(
            r"(?:https?|ftp)://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;%=]+",
            re.IGNORECASE,
        )

        for match in pattern.finditer(text):
            raw = match.group(0).rstrip("'\")];,>")
            canon_url, scheme, host, port, path, query, ip_dec, is_val = canonicalize_url(raw)
            if is_val and canon_url not in exclude:
                exclude.add(canon_url)
                results.append(
                    RemotePayloadTarget(
                        url=canon_url,
                        raw_url=raw,
                        method="regex_carve",
                        api_type="StaticCarve",
                        destination_file=None,
                        headers={},
                        cradle_type="raw_string_carve",
                        scheme=scheme,
                        host=host,
                        port=port,
                        path=path,
                        query=query,
                        ip_decoded=ip_dec,
                        is_valid_url=True,
                        confidence=0.85,
                    )
                )

        return results


def trace_webclient(
    script_or_ast: Union[str, ASTNode],
    symbols: Optional[Dict[str, Any]] = None
) -> List[RemotePayloadTarget]:
    """
    Public utility extracting remote payload download targets from a PowerShell script or AST.
    """
    tracer = PowerShellWebClientTracer(symbols=symbols)
    if isinstance(script_or_ast, str):
        return tracer.carve_text(script_or_ast)
    return tracer.trace(script_or_ast)


def carve_all_urls(
    script_or_ast: Union[str, ASTNode],
    symbols: Optional[Dict[str, Any]] = None
) -> List[RemotePayloadTarget]:
    """Alias for trace_webclient providing full-spectrum URL carving."""
    return trace_webclient(script_or_ast, symbols=symbols)


def extract_download_urls(
    script_or_ast: Union[str, ASTNode],
    symbols: Optional[Dict[str, Any]] = None
) -> List[str]:
    """
    Convenience helper returning a sorted, deduplicated list of canonical URLs.
    """
    targets = trace_webclient(script_or_ast, symbols=symbols)
    seen: Set[str] = set()
    result: List[str] = []
    for t in targets:
        if t.url not in seen:
            seen.add(t.url)
            result.append(t.url)
    return sorted(result)


__all__ = [
    "RemotePayloadTarget",
    "decode_ip_part",
    "decode_host_ip",
    "canonicalize_url",
    "WEBCLIENT_DOWNLOAD_METHODS",
    "HTTPCLIENT_DOWNLOAD_METHODS",
    "DOWNLOAD_CMDLETS",
    "PowerShellWebClientTracer",
    "trace_webclient",
    "carve_all_urls",
    "extract_download_urls",
]
