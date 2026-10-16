"""
PowerShell AST Compression Stream Reducer & Deobfuscator.
Traverses AST nodes and script text to detect, decompress, and inline in-memory
compressed streams (GzipStream, DeflateStream, BrotliStream, MemoryStream, StreamReader).
"""

import base64
import re
from typing import Any, Dict, List, Optional, Tuple, Union

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
from .compression_decompressor import (
    calculate_entropy,
    decode_stream_bytes,
    decompress_stream_bytes,
    extract_raw_byte_array,
    parse_base64_stream,
)
from .compression_models import (
    CompressionType,
    DecompressedStreamLayer,
    StreamDecompressionResult,
    StreamEncoding,
)
from .secure_string_crypto import zeroize_buffer


# Common type prefixes for stream and compression classes
GZIP_NAMES = {
    "gzipstream", "system.io.compression.gzipstream", "io.compression.gzipstream",
}
DEFLATE_NAMES = {
    "deflatestream", "system.io.compression.deflatestream", "io.compression.deflatestream",
}
BROTLI_NAMES = {
    "brotlistream", "system.io.compression.brotlistream", "io.compression.brotlistream",
}
MEMORY_STREAM_NAMES = {
    "memorystream", "system.io.memorystream", "io.memorystream",
}
STREAM_READER_NAMES = {
    "streamreader", "system.io.streamreader", "io.streamreader",
}


class PowerShellCompressionReducer:
    """
    AST Reducer and Text Evaluator that detects in-memory compressed stream constructs,
    decompresses payloads, and replaces stream reader invocations with decompressed string literals.
    """

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols: Dict[str, Any] = dict(symbols) if symbols is not None else {}
        self.stream_symbols: Dict[str, Any] = {}
        self.last_layers: List[DecompressedStreamLayer] = []

    def reduce(self, node: ASTNode) -> ASTNode:
        """Traverses and reduces compressed stream AST nodes."""
        self.stream_symbols = {}
        return self._visit(node)

    def _visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            new_stmts = [self._visit(s) for s in node.statements]
            return ScriptBlockNode(statements=new_stmts, is_nested=node.is_nested)

        elif isinstance(node, PipelineNode):
            new_elements = [self._visit(e) for e in node.elements]
            return PipelineNode(elements=new_elements)

        elif isinstance(node, AssignmentNode):
            norm_val = self._visit(node.expression)
            # Track stream and byte assignments
            if isinstance(node.variable, VariableNode):
                var_name = node.variable.name.lower()
                tracked = self._extract_stream_or_bytes(norm_val)
                if tracked:
                    self.stream_symbols[var_name] = tracked
            return AssignmentNode(variable=node.variable, expression=norm_val)

        elif isinstance(node, MethodCallNode):
            norm_target = self._visit(node.target)
            norm_args = [self._visit(a) for a in node.arguments]
            method_name = node.method_name.lower()

            # Pattern: $sr.ReadToEnd() or (New-Object ...).ReadToEnd()
            if method_name == "readtoend":
                decompressed_node = self._evaluate_readtoend(norm_target)
                if decompressed_node is not None:
                    return decompressed_node

            # Pattern: $gz.CopyTo($out)
            elif method_name == "copyto" and norm_args:
                dest_arg = norm_args[0]
                if isinstance(dest_arg, VariableNode):
                    dest_name = dest_arg.name.lower()
                    src_stream = self._resolve_stream_object(norm_target)
                    if src_stream:
                        self.stream_symbols[dest_name] = {
                            "kind": "copied_stream",
                            "source": src_stream,
                        }

            # Pattern: $out.ToArray() -> evaluate to byte array or decompressed content
            elif method_name == "toarray":
                stream_obj = self._resolve_stream_object(norm_target)
                if stream_obj:
                    decompressed_bytes = self._decompress_stream_object(stream_obj)
                    if decompressed_bytes:
                        elements = [NumberLiteralNode(value=b, raw=str(b)) for b in decompressed_bytes]
                        return ArrayLiteralNode(elements=elements)

            # Pattern: [System.Text.Encoding]::UTF8.GetString(...)
            elif method_name == "getstring" and norm_args:
                bytes_arg = norm_args[0]
                bytes_val = self._resolve_bytes(bytes_arg)
                if bytes_val:
                    enc_hint = "utf-8"
                    if isinstance(norm_target, StaticMemberAccessNode) and norm_target.member:
                        enc_hint = norm_target.member
                    clean_target = self._node_to_name(norm_target).lower()
                    if "ascii" in clean_target:
                        enc_hint = "ascii"
                    elif "unicode" in clean_target or "utf16" in clean_target:
                        enc_hint = "utf-16le"
                    text, _ = decode_stream_bytes(bytes_val, enc_hint)
                    if text:
                        return StringLiteralNode(value=text, is_expandable=False)

            return MethodCallNode(target=norm_target, method_name=node.method_name, arguments=norm_args)

        elif isinstance(node, StaticMemberAccessNode):
            # Pattern: [System.Text.Encoding]::UTF8.GetString(...)
            member_name = node.member.lower() if node.member else ""
            clean_type = node.type_name.strip("[]").lower()
            if "encoding" in clean_type and member_name == "getstring" and node.arguments:
                arg = self._visit(node.arguments[0])
                decompressed_node = self._evaluate_encoding_getstring(node, arg)
                if decompressed_node is not None:
                    return decompressed_node

            norm_args = [self._visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)

        elif isinstance(node, ParenthesizedExpressionNode):
            norm_inner = self._visit(node.expression)
            return ParenthesizedExpressionNode(expression=norm_inner)

        elif isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self._visit(s) for s in node.statements])

        elif isinstance(node, BinaryOpNode):
            return BinaryOpNode(left=self._visit(node.left), operator=node.operator, right=self._visit(node.right))

        elif isinstance(node, FormatOpNode):
            return FormatOpNode(format_string=self._visit(node.format_string), arguments=[self._visit(a) for a in node.arguments])

        elif isinstance(node, UnaryOpNode):
            return UnaryOpNode(operator=node.operator, operand=self._visit(node.operand))

        elif isinstance(node, TypeCastNode):
            return TypeCastNode(type_name=node.type_name, expression=self._visit(node.expression))

        elif isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self._visit(node.target), index=self._visit(node.index))

        elif isinstance(node, IfStatementNode):
            return IfStatementNode(
                condition=self._visit(node.condition),
                then_branch=self._visit(node.then_branch),
                else_branch=self._visit(node.else_branch) if node.else_branch else None,
            )

        elif isinstance(node, WhileStatementNode):
            return WhileStatementNode(condition=self._visit(node.condition), body=self._visit(node.body))

        elif isinstance(node, CommandNode):
            norm_target = self._visit(node.target)
            norm_args = [self._visit(a) for a in node.arguments]
            return CommandNode(target=norm_target, arguments=norm_args)

        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self._visit(e) for e in node.elements])

        return node

    def _extract_stream_or_bytes(self, node: ASTNode) -> Optional[Dict[str, Any]]:
        """Extracts stream metadata or raw bytes from an assignment value node."""
        # 1. Direct Base64 conversion: [Convert]::FromBase64String(...)
        if isinstance(node, StaticMemberAccessNode):
            clean_type = node.type_name.strip("[]").lower()
            if "convert" in clean_type and node.member.lower() == "frombase64string" and node.arguments:
                first_arg = node.arguments[0]
                raw_bytes = self._resolve_bytes(first_arg)
                if raw_bytes:
                    return {"kind": "raw_bytes", "bytes": raw_bytes}

        # String literal (can be raw base64 or text)
        if isinstance(node, StringLiteralNode):
            return {"kind": "string_literal", "text": node.value}

        # 2. Byte array literal: @(31, 139, 8, ...) or [byte[]](...)
        if isinstance(node, ArrayLiteralNode):
            raw_bytes = extract_raw_byte_array([e.value for e in node.elements if hasattr(e, "value")])
            if raw_bytes:
                return {"kind": "raw_bytes", "bytes": raw_bytes}

        if isinstance(node, TypeCastNode) and "byte" in node.type_name.lower():
            if isinstance(node.expression, ArrayLiteralNode):
                raw_bytes = extract_raw_byte_array([e.value for e in node.expression.elements if hasattr(e, "value")])
                if raw_bytes:
                    return {"kind": "raw_bytes", "bytes": raw_bytes}

        # 3. MemoryStream creation: New-Object IO.MemoryStream(...) or [IO.MemoryStream]::new(...)
        stream_info = self._parse_stream_constructor(node)
        if stream_info:
            return stream_info

        # 4. Variable alias: $b = $other
        if isinstance(node, VariableNode):
            var_name = node.name.lower()
            if var_name in self.stream_symbols:
                return self.stream_symbols[var_name]

        return None

    def _parse_stream_constructor(self, node: ASTNode) -> Optional[Dict[str, Any]]:
        """Parses New-Object, MethodCall, or ::new() constructor calls for streams."""
        target_name = ""
        args: List[ASTNode] = []

        if isinstance(node, CommandNode):
            if isinstance(node.target, IdentifierNode) and node.target.name.lower() == "new-object":
                if not node.arguments:
                    return None
                type_node = node.arguments[0]
                if isinstance(type_node, MethodCallNode):
                    args = list(type_node.arguments) + list(node.arguments[1:])
                else:
                    args = list(node.arguments[1:])
                target_name = self._node_to_name(type_node).lower()

        elif isinstance(node, MethodCallNode):
            full_name = self._node_to_name(node.target).lower()
            if full_name:
                target_name = f"{full_name}.{node.method_name}".lower()
                args = list(node.arguments)

        elif isinstance(node, StaticMemberAccessNode):
            if node.member.lower() == "new":
                target_name = node.type_name.strip("[]").lower()
                args = list(node.arguments or [])

        elif isinstance(node, ParenthesizedExpressionNode):
            return self._parse_stream_constructor(node.expression)

        if not target_name:
            return None

        clean_target = target_name.replace("`", "").strip()

        # Check MemoryStream
        if any(clean_target.endswith(m) for m in MEMORY_STREAM_NAMES) or clean_target in MEMORY_STREAM_NAMES:
            raw_bytes = None
            if args:
                raw_bytes = self._resolve_bytes(args[0])
            return {"kind": "memory_stream", "bytes": raw_bytes}

        # Check GZipStream
        if any(clean_target.endswith(g) for g in GZIP_NAMES) or clean_target in GZIP_NAMES:
            source_stream = None
            if args:
                source_stream = self._resolve_stream_object(args[0])
            return {
                "kind": "compression_stream",
                "type": CompressionType.GZIP,
                "source": source_stream,
            }

        # Check DeflateStream
        if any(clean_target.endswith(d) for d in DEFLATE_NAMES) or clean_target in DEFLATE_NAMES:
            source_stream = None
            if args:
                source_stream = self._resolve_stream_object(args[0])
            return {
                "kind": "compression_stream",
                "type": CompressionType.DEFLATE,
                "source": source_stream,
            }

        # Check BrotliStream
        if any(clean_target.endswith(b) for b in BROTLI_NAMES) or clean_target in BROTLI_NAMES:
            source_stream = None
            if args:
                source_stream = self._resolve_stream_object(args[0])
            return {
                "kind": "compression_stream",
                "type": CompressionType.BROTLI,
                "source": source_stream,
            }

        # Check StreamReader
        if any(clean_target.endswith(s) for s in STREAM_READER_NAMES) or clean_target in STREAM_READER_NAMES:
            source_stream = None
            encoding_hint = None
            if args:
                source_stream = self._resolve_stream_object(args[0])
                if len(args) > 1:
                    encoding_hint = self._extract_encoding_hint(args[1])
            return {
                "kind": "stream_reader",
                "source": source_stream,
                "encoding": encoding_hint,
            }

        return None

    def _resolve_stream_object(self, node: ASTNode) -> Optional[Dict[str, Any]]:
        """Resolves a node to its stream descriptor (from variable or direct constructor)."""
        if isinstance(node, VariableNode):
            var_name = node.name.lower()
            return self.stream_symbols.get(var_name)

        if isinstance(node, ParenthesizedExpressionNode):
            return self._resolve_stream_object(node.expression)

        return self._parse_stream_constructor(node)

    def _resolve_bytes(self, node: ASTNode) -> Optional[bytes]:
        """Resolves a node to its raw byte array."""
        if isinstance(node, VariableNode):
            var_name = node.name.lower()
            info = self.stream_symbols.get(var_name)
            if info:
                if info.get("kind") == "raw_bytes":
                    return info.get("bytes")
                if info.get("kind") == "string_literal":
                    return parse_base64_stream(info.get("text"))
                if info.get("kind") == "copied_stream":
                    return self._decompress_stream_object(info.get("source"))
            if var_name in self.symbols:
                sym_val = self.symbols[var_name]
                if isinstance(sym_val, (bytes, bytearray)):
                    return bytes(sym_val)
                if isinstance(sym_val, str):
                    b = parse_base64_stream(sym_val)
                    if b:
                        return b

        if isinstance(node, MethodCallNode) and node.method_name.lower() == "toarray":
            stream_obj = self._resolve_stream_object(node.target)
            if stream_obj:
                return self._decompress_stream_object(stream_obj)

        if isinstance(node, StaticMemberAccessNode):
            clean_type = node.type_name.strip("[]").lower()
            if "convert" in clean_type and node.member.lower() == "frombase64string" and node.arguments:
                first = node.arguments[0]
                if isinstance(first, StringLiteralNode):
                    return parse_base64_stream(first.value)
                if isinstance(first, VariableNode):
                    return self._resolve_bytes(first)

        if isinstance(node, StringLiteralNode):
            return parse_base64_stream(node.value)

        if isinstance(node, ArrayLiteralNode):
            # If wrapped in unary comma: (,[Convert]...) or @([Convert]...)
            if len(node.elements) == 1 and not isinstance(node.elements[0], (NumberLiteralNode, int)):
                return self._resolve_bytes(node.elements[0])
            return extract_raw_byte_array([e.value for e in node.elements if hasattr(e, "value")])

        if isinstance(node, TypeCastNode):
            return self._resolve_bytes(node.expression)

        if isinstance(node, ParenthesizedExpressionNode):
            return self._resolve_bytes(node.expression)

        return None

    def _evaluate_readtoend(self, target_node: ASTNode) -> Optional[StringLiteralNode]:
        """Evaluates a StreamReader ReadToEnd() call on a target node."""
        reader_obj = self._resolve_stream_object(target_node)
        if not reader_obj:
            return None

        stream_obj = reader_obj.get("source")
        if not stream_obj:
            return None

        encoding_hint = reader_obj.get("encoding")
        decompressed_bytes, comp_type = self._decompress_stream_with_type(stream_obj)
        if not decompressed_bytes:
            return None

        decompressed_text, detected_enc = decode_stream_bytes(decompressed_bytes, encoding_hint)
        if not decompressed_text:
            return None

        compressed_bytes = self._get_underlying_bytes(stream_obj) or b""
        c_size = len(compressed_bytes)
        d_size = len(decompressed_bytes)
        ratio = round(d_size / c_size, 2) if c_size > 0 else 1.0

        layer = DecompressedStreamLayer(
            depth=len(self.last_layers) + 1,
            compression_type=comp_type,
            compressed_size=c_size,
            decompressed_size=d_size,
            compression_ratio=ratio,
            detected_encoding=detected_enc,
            entropy_before=calculate_entropy(compressed_bytes),
            entropy_after=calculate_entropy(decompressed_text),
            raw_expression=f"{comp_type.value.upper()}Stream.ReadToEnd()",
            decompressed_text=decompressed_text,
        )
        self.last_layers.append(layer)

        zeroize_buffer(decompressed_bytes)
        return StringLiteralNode(value=decompressed_text, is_expandable=False)

    def _evaluate_encoding_getstring(
        self,
        enc_node: StaticMemberAccessNode,
        arg_node: ASTNode,
    ) -> Optional[StringLiteralNode]:
        """Evaluates [System.Text.Encoding]::UTF8.GetString($out.ToArray())."""
        enc_name = "utf-8"
        t_clean = enc_node.type_name.strip("[]").lower()
        if "ascii" in t_clean:
            enc_name = "ascii"
        elif "unicode" in t_clean or "utf16" in t_clean:
            enc_name = "utf-16le"

        if isinstance(arg_node, MethodCallNode) and arg_node.method_name.lower() == "toarray":
            stream_obj = self._resolve_stream_object(arg_node.target)
            if stream_obj:
                decompressed_bytes, comp_type = self._decompress_stream_with_type(stream_obj)
                if decompressed_bytes:
                    text, det = decode_stream_bytes(decompressed_bytes, enc_name)
                    if text:
                        zeroize_buffer(decompressed_bytes)
                        return StringLiteralNode(value=text, is_expandable=False)

        return None

    def _decompress_stream_with_type(
        self,
        stream_obj: Dict[str, Any],
    ) -> Tuple[Optional[bytes], CompressionType]:
        """Walks compression stream hierarchy and returns decompressed bytes + type."""
        kind = stream_obj.get("kind")

        if kind == "copied_stream":
            return self._decompress_stream_with_type(stream_obj.get("source"))

        if kind == "compression_stream":
            comp_type = stream_obj.get("type", CompressionType.UNKNOWN)
            src = stream_obj.get("source")
            raw_bytes = self._get_underlying_bytes(src)
            if not raw_bytes:
                return None, CompressionType.UNKNOWN
            decomp_bytes, detected_type = decompress_stream_bytes(raw_bytes, comp_type)
            return decomp_bytes, detected_type or comp_type

        if kind == "memory_stream":
            raw_bytes = stream_obj.get("bytes")
            if raw_bytes:
                return decompress_stream_bytes(raw_bytes, None)

        return None, CompressionType.UNKNOWN

    def _decompress_stream_object(self, stream_obj: Dict[str, Any]) -> Optional[bytes]:
        decomp, _ = self._decompress_stream_with_type(stream_obj)
        return decomp

    def _get_underlying_bytes(self, obj: Optional[Dict[str, Any]]) -> Optional[bytes]:
        """Recursively extracts raw bytes from memory stream or compression stream source."""
        if not obj:
            return None
        kind = obj.get("kind")
        if kind == "memory_stream":
            return obj.get("bytes")
        if kind == "raw_bytes":
            return obj.get("bytes")
        if kind == "compression_stream":
            return self._get_underlying_bytes(obj.get("source"))
        if kind == "copied_stream":
            return self._get_underlying_bytes(obj.get("source"))
        return None

    def _extract_encoding_hint(self, node: ASTNode) -> Optional[str]:
        """Extracts encoding hint string from AST node."""
        if isinstance(node, StaticMemberAccessNode):
            full = f"{node.type_name}::{node.member}".lower()
            if "utf8" in full:
                return "utf-8"
            if "unicode" in full:
                return "utf-16le"
            if "ascii" in full:
                return "ascii"
        name = self._node_to_name(node).lower()
        if "utf8" in name:
            return "utf-8"
        if "unicode" in name:
            return "utf-16le"
        if "ascii" in name:
            return "ascii"
        return None

    def _node_to_name(self, node: ASTNode) -> str:
        """Converts an AST node (Identifier, MemberAccess, MethodCall, TypeCast) into dot-delimited string."""
        if isinstance(node, IdentifierNode):
            return node.name
        if isinstance(node, MemberAccessNode):
            parent = self._node_to_name(node.target)
            return f"{parent}.{node.member}" if parent else node.member
        if isinstance(node, MethodCallNode):
            parent = self._node_to_name(node.target)
            return f"{parent}.{node.method_name}" if parent else node.method_name
        if isinstance(node, TypeCastNode):
            return node.type_name
        return ""

    def unwrap_text(self, text: str) -> StreamDecompressionResult:
        """
        Regex-based pattern scanning for standalone compressed stream one-liners
        and chained expressions in scripts that may contain unparsed surrounding syntax.
        """
        original = text
        current = text
        layers: List[DecompressedStreamLayer] = []

        pattern_oneliner = re.compile(
            r"\(?\s*(?:Ne`?w-Ob`?ject|\[(?:System\.)?IO\.StreamReader\]::new)\s+"
            r"(?:\(?\s*\[?(?:System\.)?IO\.StreamReader\]?\(?\s*)?"
            r"\(?\s*(?:Ne`?w-Ob`?ject|\[(?:System\.)?IO\.Compression\.(?:GZip|Deflate)Stream\]::new)\s+"
            r"(?:\(?\s*\[?(?:System\.)?IO\.Compression\.(?P<comp_kind>GZip|Deflate)Stream\]?\(?\s*)?"
            r"\(?\s*(?:Ne`?w-Ob`?ject|\[(?:System\.)?IO\.MemoryStream\]::new)\s+"
            r"(?:\(?\s*\[?(?:System\.)?IO\.MemoryStream\]?\(?\s*)?"
            r"(?:\[(?:System\.)?IO\.MemoryStream\])?\s*,?\s*"
            r"\[(?:System\.)?Convert\]::FromBase64String\(\s*['\"](?P<payload>[A-Za-z0-9+/=_\-\r\n\t` ]+)['\"]\s*\)"
            r"[^)]*\)\s*,?\s*(?:\[?(?:System\.)?IO\.Compression\.CompressionMode\]?::(?P<mode>Decompress)|1)\s*\)\s*\)?\s*\)?\s*\.ReadToEnd\(\)",
            re.IGNORECASE,
        )

        for match in pattern_oneliner.finditer(current):
            comp_kind = match.group("comp_kind").lower()
            raw_payload = match.group("payload")
            c_type = CompressionType.GZIP if "gzip" in comp_kind else CompressionType.DEFLATE

            raw_bytes = parse_base64_stream(raw_payload)
            if not raw_bytes:
                continue

            decompressed_bytes, detected_type = decompress_stream_bytes(raw_bytes, c_type)
            if not decompressed_bytes:
                continue

            decompressed_text, detected_enc = decode_stream_bytes(decompressed_bytes)
            if not decompressed_text:
                continue

            c_size = len(raw_bytes)
            d_size = len(decompressed_bytes)
            ratio = round(d_size / c_size, 2) if c_size > 0 else 1.0

            layer = DecompressedStreamLayer(
                depth=len(layers) + 1,
                compression_type=detected_type or c_type,
                compressed_size=c_size,
                decompressed_size=d_size,
                compression_ratio=ratio,
                detected_encoding=detected_enc,
                entropy_before=calculate_entropy(raw_bytes),
                entropy_after=calculate_entropy(decompressed_text),
                raw_expression=match.group(0)[:80] + "...",
                decompressed_text=decompressed_text,
            )
            layers.append(layer)
            zeroize_buffer(decompressed_bytes)

            escaped_val = decompressed_text.replace("'", "''")
            current = current.replace(match.group(0), f"'{escaped_val}'")

        pattern_multistep = re.compile(
            r"(?P<full_seq>"
            r"\$(?P<v_ms>\w+)\s*=\s*New-Object\s+(?:System\.)?IO\.MemoryStream\s*\(?\s*,?\s*\[(?:System\.)?Convert\]::FromBase64String\(\s*['\"](?P<b64>[A-Za-z0-9+/=_\-\r\n\t` ]+)['\"]\s*\)\s*\)?\s*[;\r\n]+"
            r"\$(?P<v_gz>\w+)\s*=\s*New-Object\s+(?:System\.)?IO\.Compression\.(?P<comp_kind2>GZip|Deflate)Stream\s*\(?\s*\$(?P=v_ms)\s*,\s*(?:\[(?:System\.)?IO\.Compression\.CompressionMode\]::Decompress|1)\s*\)?\s*[;\r\n]+"
            r"\$(?P<v_sr>\w+)\s*=\s*New-Object\s+(?:System\.)?IO\.StreamReader\s*\(?\s*\$(?P=v_gz)\s*\)?\s*[;\r\n]+"
            r"\$(?P<v_res>\w+)\s*=\s*\$(?P=v_sr)\.ReadToEnd\(\)"
            r")",
            re.IGNORECASE,
        )

        for match in pattern_multistep.finditer(current):
            comp_kind = match.group("comp_kind2").lower()
            raw_payload = match.group("b64")
            v_res = match.group("v_res")
            c_type = CompressionType.GZIP if "gzip" in comp_kind else CompressionType.DEFLATE

            raw_bytes = parse_base64_stream(raw_payload)
            if not raw_bytes:
                continue

            decompressed_bytes, detected_type = decompress_stream_bytes(raw_bytes, c_type)
            if not decompressed_bytes:
                continue

            decompressed_text, detected_enc = decode_stream_bytes(decompressed_bytes)
            if not decompressed_text:
                continue

            layer = DecompressedStreamLayer(
                depth=len(layers) + 1,
                compression_type=detected_type or c_type,
                compressed_size=len(raw_bytes),
                decompressed_size=len(decompressed_bytes),
                compression_ratio=round(len(decompressed_bytes) / len(raw_bytes), 2),
                detected_encoding=detected_enc,
                entropy_before=calculate_entropy(raw_bytes),
                entropy_after=calculate_entropy(decompressed_text),
                raw_expression=match.group("full_seq")[:80] + "...",
                decompressed_text=decompressed_text,
            )
            layers.append(layer)
            zeroize_buffer(decompressed_bytes)

            escaped_val = decompressed_text.replace("'", "''")
            current = current.replace(match.group("full_seq"), f"${v_res} = '{escaped_val}'")

        return StreamDecompressionResult(
            original_script=original,
            unwrapped_script=current,
            layers=layers,
            total_layers=len(layers),
            has_decompressed_streams=len(layers) > 0,
        )
