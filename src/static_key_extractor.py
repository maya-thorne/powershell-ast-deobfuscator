"""
Static Key Extraction Engine for PowerShell AST Expressions.
Analyzes syntax trees to resolve static AES keys from range expressions, array literals,
type-casted byte arrays, encoded string literals, and tracked variable symbols.
"""

import re
from typing import Any, Dict, List, Optional, Tuple, Union

from .ast_nodes import (
    ASTNode,
    ArrayLiteralNode,
    BinaryOpNode,
    IdentifierNode,
    NumberLiteralNode,
    ParenthesizedExpressionNode,
    RangeExpressionNode,
    StaticMemberAccessNode,
    StringLiteralNode,
    TypeCastNode,
    VariableNode,
)
from .secure_string_crypto import InvalidKeyLengthError


class StaticKeyExtractor:
    """
    Statically analyzes and extracts 128, 192, or 256-bit AES cryptographic keys
    from PowerShell AST nodes or runtime variable tables.
    """

    VALID_KEY_LENGTHS: Tuple[int, ...] = (16, 24, 32)

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols = symbols if symbols is not None else {}

    @classmethod
    def validate_key_length(cls, key_bytes: bytes) -> bool:
        """Verifies if the extracted byte key matches standard AES key sizes."""
        return len(key_bytes) in cls.VALID_KEY_LENGTHS

    def evaluate_integer(self, node: ASTNode) -> Optional[int]:
        """Evaluates an AST node to a static integer value."""
        if isinstance(node, NumberLiteralNode):
            try:
                return int(node.value)
            except (ValueError, TypeError):
                return None

        if isinstance(node, ParenthesizedExpressionNode):
            return self.evaluate_integer(node.expression)

        if isinstance(node, VariableNode):
            key = node.name.lower()
            if key in self.symbols:
                sym_val = self.symbols[key]
                if isinstance(sym_val, int):
                    return sym_val
                if isinstance(sym_val, str):
                    try:
                        return int(sym_val, 0)
                    except ValueError:
                        return None
                if isinstance(sym_val, ASTNode):
                    return self.evaluate_integer(sym_val)

        if isinstance(node, StringLiteralNode):
            try:
                return int(node.value.strip(), 0)
            except ValueError:
                return None

        if isinstance(node, IdentifierNode):
            try:
                return int(node.name.strip(), 0)
            except ValueError:
                return None

        if isinstance(node, BinaryOpNode):
            left_val = self.evaluate_integer(node.left)
            right_val = self.evaluate_integer(node.right)
            if left_val is not None and right_val is not None:
                if node.operator == "+":
                    return left_val + right_val
                if node.operator == "-":
                    return left_val - right_val
                if node.operator == "*":
                    return left_val * right_val
                if node.operator == "/" and right_val != 0:
                    return left_val // right_val

        return None

    def extract_key(self, node: Any) -> Optional[bytes]:
        """
        Extracts validated AES key bytes from an AST node or Python value.
        Returns bytes object if length is 16, 24, or 32 bytes; otherwise None.
        """
        if node is None:
            return None

        # Direct bytes or bytearray
        if isinstance(node, (bytes, bytearray)):
            key = bytes(node)
            return key if self.validate_key_length(key) else None

        # Python integer sequences
        if isinstance(node, (list, tuple)):
            try:
                key = bytes(int(x) & 0xFF for x in node)
                return key if self.validate_key_length(key) else None
            except (ValueError, TypeError):
                return None

        # Parenthesized expression: (1..16)
        if isinstance(node, ParenthesizedExpressionNode):
            return self.extract_key(node.expression)

        # Type cast: [byte[]](1..16) or [byte[]]@(1,2...)
        if isinstance(node, TypeCastNode):
            target = getattr(node, "expression", getattr(node, "target", None))
            return self.extract_key(target)

        # Range expression: 1..16 or 32..1
        if isinstance(node, RangeExpressionNode):
            start = self.evaluate_integer(node.start)
            end = self.evaluate_integer(node.end)
            if start is not None and end is not None:
                step = 1 if start <= end else -1
                rng = range(start, end + step, step)
                key = bytes(b & 0xFF for b in rng)
                return key if self.validate_key_length(key) else None

        # Binary range operator: 1 .. 16
        if isinstance(node, BinaryOpNode) and node.operator == "..":
            start = self.evaluate_integer(node.left)
            end = self.evaluate_integer(node.right)
            if start is not None and end is not None:
                step = 1 if start <= end else -1
                rng = range(start, end + step, step)
                key = bytes(b & 0xFF for b in rng)
                return key if self.validate_key_length(key) else None

        # Array literal: @(1, 2, 3...) or @(0x01, 0x02...)
        if isinstance(node, ArrayLiteralNode):
            byte_values: List[int] = []
            for elem in node.elements:
                int_val = self.evaluate_integer(elem)
                if int_val is None:
                    # Check if nested range expression inside array: @(1..16)
                    sub_key = self.extract_key(elem)
                    if sub_key is not None:
                        byte_values.extend(sub_key)
                        continue
                    return None
                byte_values.append(int_val & 0xFF)
            key = bytes(byte_values)
            return key if self.validate_key_length(key) else None

        # Variable resolution: $k
        if isinstance(node, VariableNode):
            var_name = node.name.lower()
            if var_name in self.symbols:
                sym_val = self.symbols[var_name]
                return self.extract_key(sym_val)

        # String literal with exact length: 'MySecretKey12345'
        if isinstance(node, StringLiteralNode):
            raw_bytes = node.value.encode("utf-8")
            if self.validate_key_length(raw_bytes):
                return raw_bytes

        # Static member encoding: [System.Text.Encoding]::UTF8.GetBytes("key")
        if isinstance(node, StaticMemberAccessNode):
            if "encoding" in node.type_name.lower() and node.member.lower() == "getbytes":
                if node.arguments and len(node.arguments) > 0:
                    arg = node.arguments[0]
                    if isinstance(arg, StringLiteralNode):
                        raw_bytes = arg.value.encode("utf-8")
                        if self.validate_key_length(raw_bytes):
                            return raw_bytes

        # Fallback textual identifier pattern: "1..16"
        if isinstance(node, IdentifierNode):
            match = re.match(r"^(\d+)\.\.(\d+)$", node.name.strip())
            if match:
                s, e = int(match.group(1)), int(match.group(2))
                step = 1 if s <= e else -1
                key = bytes(b & 0xFF for b in range(s, e + step, step))
                return key if self.validate_key_length(key) else None

        return None
