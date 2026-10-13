"""
PowerShell Base64 Encoded Command Recursive Unwrapper.
Detects, extracts, normalizes, and recursively unwraps nested -EncodedCommand, -enc, -e
parameters across CLI command strings and AST CommandNodes.
"""

import base64
from collections import Counter
from dataclasses import dataclass, field
import hashlib
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .ast_nodes import (
    ASTNode,
    ArrayLiteralNode,
    BinaryOpNode,
    CommandNode,
    IdentifierNode,
    MethodCallNode,
    ParenthesizedExpressionNode,
    PipelineNode,
    ScriptBlockNode,
    StaticMemberAccessNode,
    StringLiteralNode,
)
from .lexer import PowerShellLexer
from .parser import PowerShellParser
from .secure_string_crypto import zeroize_buffer


# Set of valid PowerShell CLI parameter prefixes for -EncodedCommand
VALID_ENCODED_ALIASES = {
    "e", "en", "enc", "enco", "encod", "encode", "encoded",
    "encodedc", "encodedco", "encodedcom", "encodedcomm",
    "encodedcomma", "encodedcomman", "encodedcommand",
}


@dataclass
class EncodedCommandLayer:
    """Represents a single layer of an unwrapped Base64 encoded PowerShell command."""
    depth: int
    raw_command: str
    cli_binary: Optional[str]
    flags: List[str]
    b64_payload: str
    detected_encoding: str
    decoded_content: str
    entropy_before: float
    entropy_after: float


@dataclass
class UnwrapResult:
    """Comprehensive result of recursive encoded command unwrapping."""
    original_script: str
    unwrapped_script: str
    layers: List[EncodedCommandLayer] = field(default_factory=list)
    total_layers: int = 0
    has_encoded_commands: bool = False


def calculate_entropy(data: Union[str, bytes]) -> float:
    """
    Calculates Shannon entropy in bits per symbol (0.0 to 8.0).
    Higher entropy indicates obfuscated, encrypted, or Base64-encoded content.
    """
    if not data:
        return 0.0
    if isinstance(data, str):
        byte_data = data.encode("utf-8", errors="ignore")
    else:
        byte_data = data
    if not byte_data:
        return 0.0
    length = len(byte_data)
    counts = Counter(byte_data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_encoded_command_flag(flag: str) -> bool:
    """
    Checks whether an argument token matches PowerShell's -EncodedCommand parameter or aliases.
    Handles leading dashes (-), forward slashes (/), backticks, and colon/equals delimiters.
    """
    if not flag:
        return False
    clean = flag.strip().replace("`", "")
    if not (clean.startswith("-") or clean.startswith("/")):
        return False
    name = clean[1:].lower()
    if ":" in name:
        name = name.split(":", 1)[0]
    elif "=" in name:
        name = name.split("=", 1)[0]
    return name in VALID_ENCODED_ALIASES


def decode_b64_payload(b64_str: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Cleans, pads, and decodes Base64 payload with multi-encoding auto-detection.
    Supports UTF-16LE (standard PowerShell), UTF-8, UTF-16BE, ASCII, and Latin-1.
    Performs memory zeroization on decoded byte buffers.
    """
    if not b64_str:
        return None, None

    # 1. Clean payload: strip outer quotes and backtick obfuscation
    clean = b64_str.strip()
    if (clean.startswith("'") and clean.endswith("'")) or (clean.startswith('"') and clean.endswith('"')):
        clean = clean[1:-1].strip()
    clean = clean.replace("`", "")

    # Strip internal whitespace, tabs, and newlines that PowerShell FromBase64String ignores
    clean = re.sub(r"[\s\r\n\t]+", "", clean)
    if len(clean) < 4:
        return None, None

    # 2. Normalize URL-safe Base64 variants (- to +, _ to /)
    normalized = clean.replace("-", "+").replace("_", "/")

    # 3. Repair missing padding
    rem = len(normalized) % 4
    if rem == 2:
        normalized += "=="
    elif rem == 3:
        normalized += "="
    elif rem == 1:
        normalized = normalized[:-1]

    # 4. Decode bytes
    raw_bytes = None
    try:
        raw_bytes = base64.b64decode(normalized, validate=False)
    except Exception:
        try:
            raw_bytes = base64.urlsafe_b64decode(normalized)
        except Exception:
            return None, None

    if not raw_bytes or len(raw_bytes) == 0:
        return None, None

    decoded_text: Optional[str] = None
    detected_encoding: Optional[str] = None

    # 5. Multi-encoding detection with BOM checks
    if raw_bytes.startswith(b"\xff\xfe"):
        try:
            decoded_text = raw_bytes[2:].decode("utf-16le")
            detected_encoding = "utf-16le"
        except Exception:
            pass
    elif raw_bytes.startswith(b"\xef\xbb\xbf"):
        try:
            decoded_text = raw_bytes[3:].decode("utf-8")
            detected_encoding = "utf-8"
        except Exception:
            pass
    elif raw_bytes.startswith(b"\xfe\xff"):
        try:
            decoded_text = raw_bytes[2:].decode("utf-16be")
            detected_encoding = "utf-16be"
        except Exception:
            pass

    # Heuristic for UTF-16LE vs UTF-8:
    # Genuine UTF-16LE scripts of ASCII characters contain ~50% null bytes (\x00).
    # If null byte count is 0, payload is pure UTF-8 or ASCII (not UTF-16LE).
    null_count = raw_bytes.count(0)
    has_utf16_nulls = null_count >= max(1, len(raw_bytes) // 4)

    if decoded_text is None and has_utf16_nulls:
        # Check UTF-16LE
        try:
            u16_bytes = raw_bytes if len(raw_bytes) % 2 == 0 else raw_bytes[:-1]
            candidate_u16 = u16_bytes.decode("utf-16le", errors="replace")
            if "\ufffd" not in candidate_u16 and len(candidate_u16) > 0:
                printable_count = sum(1 for c in candidate_u16 if c.isprintable() or c in "\r\n\t")
                if (printable_count / len(candidate_u16)) >= 0.75:
                    decoded_text = candidate_u16
                    detected_encoding = "utf-16le"
        except Exception:
            pass

    # Check UTF-8 (especially if 0 null bytes or UTF-16LE failed)
    if decoded_text is None:
        try:
            candidate_u8 = raw_bytes.decode("utf-8", errors="replace")
            if "\ufffd" not in candidate_u8 and len(candidate_u8) > 0:
                printable_count = sum(1 for c in candidate_u8 if c.isprintable() or c in "\r\n\t")
                if (printable_count / len(candidate_u8)) >= 0.75:
                    decoded_text = candidate_u8
                    detected_encoding = "utf-8"
        except Exception:
            pass

    # Fallback to UTF-16LE if UTF-8 failed even without high null count
    if decoded_text is None:
        try:
            u16_bytes = raw_bytes if len(raw_bytes) % 2 == 0 else raw_bytes[:-1]
            candidate_u16 = u16_bytes.decode("utf-16le", errors="replace")
            if "\ufffd" not in candidate_u16 and len(candidate_u16) > 0:
                printable_count = sum(1 for c in candidate_u16 if c.isprintable() or c in "\r\n\t")
                if (printable_count / len(candidate_u16)) >= 0.75:
                    decoded_text = candidate_u16
                    detected_encoding = "utf-16le"
        except Exception:
            pass

    # Fallback candidates: ASCII / Latin-1
    if decoded_text is None:
        try:
            candidate_ascii = raw_bytes.decode("ascii")
            if all(c.isprintable() or c in "\r\n\t" for c in candidate_ascii):
                decoded_text = candidate_ascii
                detected_encoding = "ascii"
        except Exception:
            try:
                candidate_lat = raw_bytes.decode("latin-1")
                printable_count = sum(1 for c in candidate_lat if c.isprintable() or c in "\r\n\t")
                if len(candidate_lat) > 0 and (printable_count / len(candidate_lat)) >= 0.85:
                    decoded_text = candidate_lat
                    detected_encoding = "latin-1"
            except Exception:
                pass

    # 6. Memory scrubbing of raw decoded buffer
    zeroize_buffer(bytearray(raw_bytes))

    return decoded_text, detected_encoding


class PowerShellEncodedCommandUnwrapper:
    """
    Compiler-grade recursive unwrap engine for Base64 encoded PowerShell commands.
    Handles CLI command strings, script blocks, parenthesized concatenations, and AST nodes.
    """

    MAX_RECURSION_DEPTH = 50

    def __init__(
        self,
        symbols: Optional[Dict[str, Any]] = None,
        max_depth: int = MAX_RECURSION_DEPTH,
        inline_ast: bool = True,
    ):
        self.symbols = symbols if symbols is not None else {}
        self.max_depth = max_depth
        self.inline_ast = inline_ast

    def unwrap(self, target: Union[str, ASTNode]) -> Union[str, ASTNode]:
        """Unified entry point accepting either a script text string or an ASTNode."""
        if isinstance(target, str):
            res = self.unwrap_text(target)
            return res.unwrapped_script
        elif isinstance(target, ASTNode):
            return self.unwrap_ast(target)
        return target

    def unwrap_text(self, text: str, max_depth: Optional[int] = None) -> UnwrapResult:
        """
        Recursively unwraps all Base64 encoded command invocations in text.
        Tracks each unwrap layer and detects cyclic loops.
        """
        limit = max_depth if max_depth is not None else self.max_depth
        current = text.strip()
        layers: List[EncodedCommandLayer] = []
        seen_hashes: Set[str] = set()
        depth = 0

        while depth < limit:
            # Loop protection via SHA-256 hash tracking
            current_hash = hashlib.sha256(current.encode("utf-8", errors="ignore")).hexdigest()
            if current_hash in seen_hashes:
                break
            seen_hashes.add(current_hash)

            new_text, pass_layers = self._unwrap_text_single_pass(current, depth + 1)
            if not pass_layers:
                break

            layers.extend(pass_layers)
            current = new_text.strip()
            depth += 1

        return UnwrapResult(
            original_script=text,
            unwrapped_script=current,
            layers=layers,
            total_layers=len(layers),
            has_encoded_commands=len(layers) > 0,
        )

    def extract_layers(self, text: str) -> List[EncodedCommandLayer]:
        """Extracts all decoded layers from text without mutating the original string."""
        res = self.unwrap_text(text)
        return res.layers

    def _unwrap_text_single_pass(
        self, text: str, current_depth: int
    ) -> Tuple[str, List[EncodedCommandLayer]]:
        """Scans and unwraps one layer of encoded commands across the input script string."""
        layers: List[EncodedCommandLayer] = []

        # Unified regex matching both binary-prefixed invocations and standalone -enc parameters
        pattern = re.compile(
            r"""
            (?P<match_all>
                (?P<prefix>
                    (?:(?:&|\.)\s+)?
                    (?:['"]?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?\s*/c\s*powershell(?:\.exe)?)['"]?\s+)
                )?
                (?P<flags_before>
                    (?:
                        [-/][a-zA-Z0-9_`]+
                        (?::\S+|=["'][^"']*["']|=\S+|\s+(?![-/])[^\s;|\n]+)?
                        \s*
                    )*
                )
                (?P<enc_flag>
                    [-/][a-zA-Z0-9_`]+
                )
                (?P<sep>
                    [:=\s]+
                )
                (?P<payload>
                    \((?:'[^']*'|"[^"]*"|[\s+A-Za-z0-9+/=_\-`])+\)
                    |'[^']+'
                    |"[^"]+"
                    |[A-Za-z0-9+/=_\-`]{4,}
                )
            )
            """,
            re.VERBOSE | re.IGNORECASE,
        )

        def replace_callback(m: re.Match) -> str:
            enc_flag = m.group("enc_flag")
            if not is_encoded_command_flag(enc_flag):
                return m.group(0)

            raw_payload = m.group("payload").strip()
            clean_b64 = self._extract_b64_string(raw_payload)
            if not clean_b64:
                return m.group(0)

            decoded_script, enc_name = decode_b64_payload(clean_b64)
            if decoded_script is None or enc_name is None:
                return m.group(0)

            prefix = m.group("prefix") or ""
            cli_bin = self._extract_cli_binary(prefix)
            flags = self._extract_flag_list(m.group("flags_before") or "")

            layer = EncodedCommandLayer(
                depth=current_depth,
                raw_command=m.group("match_all").strip(),
                cli_binary=cli_bin,
                flags=flags,
                b64_payload=clean_b64,
                detected_encoding=enc_name,
                decoded_content=decoded_script,
                entropy_before=calculate_entropy(clean_b64),
                entropy_after=calculate_entropy(decoded_script),
            )
            layers.append(layer)
            return decoded_script.strip()

        unwrapped = pattern.sub(replace_callback, text)
        return unwrapped, layers

    def _extract_b64_string(self, raw_payload: str) -> str:
        """Extracts clean base64 string from quotes, parentheses, or string concatenations."""
        payload = raw_payload.strip()

        # Handle parenthesized expressions like ('part1' + 'part2')
        if payload.startswith("(") and payload.endswith(")"):
            inner = payload[1:-1].strip()
            # If concatenation with '+', collect and merge string literals
            if "+" in inner:
                parts = re.findall(r"['\"]([^'\"]*)['\"]", inner)
                if parts:
                    return "".join(parts).replace("`", "")
            payload = inner

        # Strip surrounding quotes
        if (payload.startswith("'") and payload.endswith("'")) or (
            payload.startswith('"') and payload.endswith('"')
        ):
            payload = payload[1:-1].strip()

        return payload.replace("`", "")

    def _extract_cli_binary(self, prefix: str) -> Optional[str]:
        """Extracts CLI executable name from command prefix."""
        clean = prefix.strip().replace("'", "").replace('"', "")
        clean = re.sub(r"^(?:&|\.)\s*", "", clean)
        m = re.search(r"\b(powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?)\b", clean, re.IGNORECASE)
        if m:
            return m.group(1).lower()
        return None

    def _extract_flag_list(self, flags_text: str) -> List[str]:
        """Extracts list of CLI flags before -EncodedCommand."""
        return re.findall(r"[-/][a-zA-Z0-9_`]+(?::\S+|=\S+)?", flags_text)

    def unwrap_ast(self, node: ASTNode) -> ASTNode:
        """Traverses AST and unwraps CommandNode instances containing -EncodedCommand."""
        visitor = _EncodedCommandASTVisitor(self, inline_ast=self.inline_ast)
        return visitor.visit(node)


class _EncodedCommandASTVisitor:
    """AST visitor traversing and resolving Base64 encoded commands in syntax trees."""

    def __init__(self, unwrapper: PowerShellEncodedCommandUnwrapper, inline_ast: bool = True):
        self.unwrapper = unwrapper
        self.inline_ast = inline_ast

    def visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            return ScriptBlockNode(
                statements=[self.visit(s) for s in node.statements],
                is_nested=node.is_nested,
            )
        elif isinstance(node, PipelineNode):
            norm_elements = [self.visit(e) for e in node.elements]
            if len(norm_elements) == 1:
                return norm_elements[0]
            return PipelineNode(elements=norm_elements)
        elif isinstance(node, CommandNode):
            return self.visit_command(node)
        elif isinstance(node, ParenthesizedExpressionNode):
            return ParenthesizedExpressionNode(expression=self.visit(node.expression))
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        elif isinstance(node, MethodCallNode):
            return MethodCallNode(
                target=self.visit(node.target),
                method_name=node.method_name,
                arguments=[self.visit(a) for a in node.arguments],
            )
        elif isinstance(node, StaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)
        return node

    def visit_command(self, node: CommandNode) -> ASTNode:
        norm_target = self.visit(node.target)
        norm_args = [self.visit(a) for a in node.arguments]

        target_name = self._get_node_name(norm_target).lower()

        # Handle & { ... } where argument is a ScriptBlockNode
        if target_name in ("&", "."):
            if len(norm_args) == 1 and isinstance(norm_args[0], ScriptBlockNode):
                sb = norm_args[0]
                if len(sb.statements) == 1:
                    return sb.statements[0]
                return sb

        # 1. Inspect arguments for -EncodedCommand parameter
        for i, arg in enumerate(norm_args):
            arg_str = self._get_node_name(arg)
            if not is_encoded_command_flag(arg_str):
                continue

            # Check if payload is joined via colon/equals (-enc:Payload or -enc=Payload)
            b64_str: Optional[str] = None
            if ":" in arg_str:
                b64_str = arg_str.split(":", 1)[1]
            elif "=" in arg_str:
                b64_str = arg_str.split("=", 1)[1]
            elif i + 1 < len(norm_args):
                b64_str = self._extract_payload_from_arg(norm_args[i + 1])

            if not b64_str:
                continue

            decoded_script, enc_name = decode_b64_payload(b64_str)
            if not decoded_script:
                continue

            if self.inline_ast:
                try:
                    lexer = PowerShellLexer(decoded_script)
                    tokens = lexer.tokenize()
                    parser = PowerShellParser(tokens)
                    parsed_ast = parser.parse()
                    # Recursively unwrap inner AST layers
                    inner_unwrapped = self.visit(parsed_ast)
                    if isinstance(inner_unwrapped, ScriptBlockNode) and len(inner_unwrapped.statements) == 1:
                        return inner_unwrapped.statements[0]
                    return inner_unwrapped
                except Exception:
                    pass

            # Fallback representation: replace -enc <b64> with -Command <decoded>
            new_args: List[ASTNode] = []
            skip_next = not (":" in arg_str or "=" in arg_str)
            for j, a in enumerate(norm_args):
                if j == i:
                    new_args.append(IdentifierNode(name="-Command"))
                    new_args.append(StringLiteralNode(value=decoded_script, is_expandable=False))
                elif skip_next and j == i + 1:
                    continue
                else:
                    new_args.append(a)
            return CommandNode(target=norm_target, arguments=new_args)

        # 2. Start-Process powershell -ArgumentList "-enc <b64>"
        if target_name == "start-process":
            for i, arg in enumerate(norm_args):
                if isinstance(arg, StringLiteralNode) and "-enc" in arg.value.lower():
                    unwrapped_arg = self.unwrapper.unwrap_text(arg.value).unwrapped_script
                    norm_args[i] = StringLiteralNode(value=unwrapped_arg, is_expandable=arg.is_expandable)

        return CommandNode(target=norm_target, arguments=norm_args)

    def _get_node_name(self, node: ASTNode) -> str:
        """Retrieves raw string representation of Identifier or StringLiteral nodes."""
        if isinstance(node, IdentifierNode):
            return node.name
        elif isinstance(node, StringLiteralNode):
            return node.value
        return ""

    def _extract_payload_from_arg(self, node: ASTNode) -> Optional[str]:
        """Extracts Base64 string from AST node (StringLiteral, Identifier, Parenthesized)."""
        if isinstance(node, StringLiteralNode):
            return node.value
        elif isinstance(node, IdentifierNode):
            return node.name
        elif isinstance(node, ParenthesizedExpressionNode):
            return self._extract_payload_from_arg(node.expression)
        elif isinstance(node, BinaryOpNode) and node.operator == "+":
            left = self._extract_payload_from_arg(node.left)
            right = self._extract_payload_from_arg(node.right)
            if left is not None and right is not None:
                return left + right
        return None
