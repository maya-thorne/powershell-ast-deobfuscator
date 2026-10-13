"""
PowerShell Type Casting Mangling & Array Shuffling Resolver.
Evaluates and simplifies type accelerators, char/byte casts, array index shuffling,
reverse slices, join operations, and type reflection into canonical syntax.
"""

import base64
import re
from typing import Any, Dict, List, Optional, Union

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
from .secure_string_crypto import zeroize_buffer
from .type_accelerators import TypeAcceleratorRegistry


class PowerShellTypeCastingResolver:
    """
    AST Visitor and Evaluator that resolves PowerShell type casts, array shuffling,
    reverse slices, and join operations to reduce obfuscation.
    """

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols = symbols if symbols is not None else {}

    def resolve(self, node: ASTNode) -> ASTNode:
        return self.visit(node)

    def visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            return ScriptBlockNode(statements=[self.visit(s) for s in node.statements])
        elif isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self.visit(s) for s in node.statements])
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, CommandNode):
            return CommandNode(target=self.visit(node.target), arguments=[self.visit(a) for a in node.arguments])
        elif isinstance(node, ParenthesizedExpressionNode):
            inner = self.visit(node.expression)
            if isinstance(inner, (StringLiteralNode, NumberLiteralNode, IdentifierNode)):
                return inner
            return ParenthesizedExpressionNode(expression=inner)
        elif isinstance(node, AssignmentNode):
            return AssignmentNode(variable=node.variable, expression=self.visit(node.expression))
        elif isinstance(node, BinaryOpNode):
            return self.visit_binary_op(node)
        elif isinstance(node, UnaryOpNode):
            return self.visit_unary_op(node)
        elif isinstance(node, TypeCastNode):
            return self.visit_type_cast(node)
        elif isinstance(node, IndexAccessNode):
            return self.visit_index_access(node)
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        elif isinstance(node, RangeExpressionNode):
            return RangeExpressionNode(start=self.visit(node.start), end=self.visit(node.end))
        elif isinstance(node, MemberAccessNode):
            return self.visit_member_access(node)
        elif isinstance(node, StaticMemberAccessNode):
            return self.visit_static_member(node)
        elif isinstance(node, MethodCallNode):
            return self.visit_method_call(node)
        elif isinstance(node, FormatOpNode):
            return FormatOpNode(format_string=self.visit(node.format_string), arguments=[self.visit(a) for a in node.arguments])
        return node

    def visit_pipeline(self, node: PipelineNode) -> ASTNode:
        norm_elements = [self.visit(e) for e in node.elements]
        # Check for pipeline char conversion: (73, 69, 88) | % { [char]$_ }
        if len(norm_elements) == 2:
            left, right = norm_elements[0], norm_elements[1]
            if isinstance(left, (ArrayLiteralNode, ParenthesizedExpressionNode)):
                # If right is ForEach-Object / % block converting to char
                if isinstance(right, CommandNode):
                    cmd_name = getattr(right.target, "name", "")
                    if cmd_name.lower() in ("%", "foreach-object", "foreach"):
                        char_arr = self._try_eval_foreach_char(left, right)
                        if char_arr:
                            return char_arr
        if len(norm_elements) == 1:
            return norm_elements[0]
        return PipelineNode(elements=norm_elements)

    def _try_eval_foreach_char(self, left: ASTNode, cmd: CommandNode) -> Optional[ArrayLiteralNode]:
        """Evaluates pipeline items mapped via [char]$_."""
        items = self._extract_integer_list(left)
        if items is None:
            return None
        # Check if argument contains [char]$_
        cmd_str = str(cmd.arguments)
        if "[char]" in cmd_str.lower() or "char" in cmd_str.lower():
            char_nodes = [StringLiteralNode(value=chr(i & 0x10FFFF)) for i in items]
            return ArrayLiteralNode(elements=char_nodes)
        return None

    def visit_type_cast(self, node: TypeCastNode) -> ASTNode:
        canonical_alias = TypeAcceleratorRegistry.get_canonical_alias(node.type_name).lower()
        expr = self.visit(node.expression)

        # 1. [char] cast
        if canonical_alias == "char":
            return self._eval_char_cast(expr)

        # 2. [int], [int32], [int16], [int64], [byte] casts
        if canonical_alias in ("int", "int32", "int16", "int64", "byte", "uint32"):
            return self._eval_int_or_byte_cast(canonical_alias, expr)

        # 3. [char[]] cast
        if canonical_alias == "char[]":
            return self._eval_char_array_cast(expr)

        # 4. [byte[]] cast
        if canonical_alias == "byte[]":
            return self._eval_byte_array_cast(expr)

        # 5. [string] cast
        if canonical_alias == "string":
            return self._eval_string_cast(expr)

        # 6. [type] cast
        if canonical_alias == "type":
            if isinstance(expr, StringLiteralNode):
                full_type = TypeAcceleratorRegistry.resolve_full_type(expr.value)
                return IdentifierNode(name=f"[{full_type}]")

        return TypeCastNode(type_name=node.type_name, expression=expr)

    def _eval_char_cast(self, expr: ASTNode) -> ASTNode:
        # If [char][int]... (nested cast)
        if isinstance(expr, TypeCastNode):
            expr = self.visit_type_cast(expr)

        if isinstance(expr, NumberLiteralNode):
            try:
                val = int(expr.value)
                if 0 <= val <= 0x10FFFF:
                    return StringLiteralNode(value=chr(val), is_expandable=False)
            except (ValueError, OverflowError):
                pass

        if isinstance(expr, StringLiteralNode):
            s = expr.value.strip()
            # Hex string '0x41'
            if s.startswith(("0x", "0X")):
                try:
                    val = int(s, 16)
                    return StringLiteralNode(value=chr(val), is_expandable=False)
                except ValueError:
                    pass
            # Decimal string '65'
            if s.isdigit():
                try:
                    val = int(s)
                    return StringLiteralNode(value=chr(val), is_expandable=False)
                except ValueError:
                    pass
            if len(s) == 1:
                return StringLiteralNode(value=s, is_expandable=False)

        return TypeCastNode(type_name="char", expression=expr)

    def _eval_int_or_byte_cast(self, type_alias: str, expr: ASTNode) -> ASTNode:
        if isinstance(expr, NumberLiteralNode):
            val = int(expr.value)
            if type_alias == "byte":
                val = val & 0xFF
            return NumberLiteralNode(value=val, raw=str(val))

        if isinstance(expr, StringLiteralNode):
            s = expr.value.strip()
            if s.startswith(("0x", "0X")):
                try:
                    val = int(s, 16)
                    if type_alias == "byte":
                        val = val & 0xFF
                    return NumberLiteralNode(value=val, raw=str(val))
                except ValueError:
                    pass
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                try:
                    val = int(s)
                    if type_alias == "byte":
                        val = val & 0xFF
                    return NumberLiteralNode(value=val, raw=str(val))
                except ValueError:
                    pass
            if len(s) == 1:
                val = ord(s)
                if type_alias == "byte":
                    val = val & 0xFF
                return NumberLiteralNode(value=val, raw=str(val))

        return TypeCastNode(type_name=type_alias, expression=expr)

    def _eval_char_array_cast(self, expr: ASTNode) -> ASTNode:
        # [char[]]"hello" -> ArrayLiteralNode of chars
        if isinstance(expr, StringLiteralNode):
            char_nodes = [StringLiteralNode(value=c, is_expandable=False) for c in expr.value]
            return ArrayLiteralNode(elements=char_nodes)

        # [char[]](73, 69, 88) or [char[]]@(73, 69, 88)
        items = self._extract_integer_list(expr)
        if items is not None:
            char_nodes = [StringLiteralNode(value=chr(i & 0x10FFFF), is_expandable=False) for i in items]
            return ArrayLiteralNode(elements=char_nodes)

        return TypeCastNode(type_name="char[]", expression=expr)

    def _eval_byte_array_cast(self, expr: ASTNode) -> ASTNode:
        items = self._extract_integer_list(expr)
        if items is not None:
            byte_nodes = [NumberLiteralNode(value=i & 0xFF, raw=str(i & 0xFF)) for i in items]
            return ArrayLiteralNode(elements=byte_nodes)

        return TypeCastNode(type_name="byte[]", expression=expr)

    def _eval_string_cast(self, expr: ASTNode) -> ASTNode:
        # [string][char[]](73, 69, 88) -> 'IEX'
        if isinstance(expr, TypeCastNode) and TypeAcceleratorRegistry.get_canonical_alias(expr.type_name).lower() == "char[]":
            char_array = self._eval_char_array_cast(expr.expression)
            if isinstance(char_array, ArrayLiteralNode):
                return self._join_elements(char_array.elements, delimiter="")

        # [string](ArrayLiteralNode of chars)
        if isinstance(expr, ArrayLiteralNode):
            all_chars = all(isinstance(e, StringLiteralNode) for e in expr.elements)
            if all_chars:
                return self._join_elements(expr.elements, delimiter="")

        if isinstance(expr, NumberLiteralNode):
            return StringLiteralNode(value=str(expr.value), is_expandable=False)

        if isinstance(expr, StringLiteralNode):
            return expr

        return TypeCastNode(type_name="string", expression=expr)

    def visit_index_access(self, node: IndexAccessNode) -> ASTNode:
        target = self.visit(node.target)
        index = self.visit(node.index)

        # Unwrap ParenthesizedExpressionNode if simple
        if isinstance(target, ParenthesizedExpressionNode):
            target = target.expression

        # Resolve index list: single int, list of ints, or range
        index_list = self._extract_index_list(index)
        if index_list is None:
            return IndexAccessNode(target=target, index=index)

        # Case 1: Target is StringLiteralNode: 'hello'[1] or 'olleh'[4..0] or 'xesi'[3,0,1,2]
        if isinstance(target, StringLiteralNode):
            s = target.value
            length = len(s)
            if length == 0:
                return StringLiteralNode(value="")

            # Single index access: 'hello'[1] -> 'e'
            if len(index_list) == 1 and not isinstance(index, (ArrayLiteralNode, RangeExpressionNode)):
                idx = index_list[0]
                if -length <= idx < length:
                    return StringLiteralNode(value=s[idx], is_expandable=False)

            # Multiple indices / range: 'olleh'[4, 3, 2, 1, 0] or 'olleh'[4..0] -> ArrayLiteralNode of chars
            extracted = []
            for idx in index_list:
                if -length <= idx < length:
                    extracted.append(StringLiteralNode(value=s[idx], is_expandable=False))
            return ArrayLiteralNode(elements=extracted)

        # Case 2: Target is ArrayLiteralNode: @(10, 20)[0] or [char[]](88,69,73)[2,1,0]
        if isinstance(target, ArrayLiteralNode):
            elements = target.elements
            length = len(elements)
            if length == 0:
                return ArrayLiteralNode(elements=[])

            # Single index access: returns the element
            if len(index_list) == 1 and not isinstance(index, (ArrayLiteralNode, RangeExpressionNode)):
                idx = index_list[0]
                if -length <= idx < length:
                    return elements[idx]

            # Multiple indices: returns reordered ArrayLiteralNode
            shuffled = []
            for idx in index_list:
                if -length <= idx < length:
                    shuffled.append(elements[idx])
            return ArrayLiteralNode(elements=shuffled)

        # Case 3: Target is [char[]] or [byte[]] TypeCastNode
        if isinstance(target, TypeCastNode):
            alias = TypeAcceleratorRegistry.get_canonical_alias(target.type_name).lower()
            if alias == "char[]":
                arr = self._eval_char_array_cast(target.expression)
                if isinstance(arr, ArrayLiteralNode):
                    return self.visit_index_access(IndexAccessNode(target=arr, index=index))
            elif alias == "byte[]":
                arr = self._eval_byte_array_cast(target.expression)
                if isinstance(arr, ArrayLiteralNode):
                    return self.visit_index_access(IndexAccessNode(target=arr, index=index))

        return IndexAccessNode(target=target, index=index)

    def visit_unary_op(self, node: UnaryOpNode) -> ASTNode:
        operand = self.visit(node.operand)

        if node.operator.lower() == "-join":
            # Unwrap parenthesized expression
            if isinstance(operand, ParenthesizedExpressionNode):
                operand = operand.expression

            # If operand is ArrayLiteralNode: -join ('h', 'e', 'l', 'l', 'o')
            if isinstance(operand, ArrayLiteralNode):
                return self._join_elements(operand.elements, delimiter="")

            # If operand is StringLiteralNode: -join 'hello' -> 'hello'
            if isinstance(operand, StringLiteralNode):
                return operand

            # If operand is [char[]](...) cast
            if isinstance(operand, TypeCastNode) and TypeAcceleratorRegistry.get_canonical_alias(operand.type_name).lower() == "char[]":
                arr = self._eval_char_array_cast(operand.expression)
                if isinstance(arr, ArrayLiteralNode):
                    return self._join_elements(arr.elements, delimiter="")

        return UnaryOpNode(operator=node.operator, operand=operand)

    def visit_binary_op(self, node: BinaryOpNode) -> ASTNode:
        left = self.visit(node.left)
        right = self.visit(node.right)

        # Binary -join: left -join delimiter
        if node.operator.lower() == "-join":
            # Unwrap parentheses
            if isinstance(left, ParenthesizedExpressionNode):
                left = left.expression

            delimiter = right.value if isinstance(right, StringLiteralNode) else ""

            # If left is ArrayLiteralNode
            if isinstance(left, ArrayLiteralNode):
                return self._join_elements(left.elements, delimiter=delimiter)

            # If left is TypeCastNode [char[]](...)
            if isinstance(left, TypeCastNode) and TypeAcceleratorRegistry.get_canonical_alias(left.type_name).lower() == "char[]":
                arr = self._eval_char_array_cast(left.expression)
                if isinstance(arr, ArrayLiteralNode):
                    return self._join_elements(arr.elements, delimiter=delimiter)

            # If left is already a string literal
            if isinstance(left, StringLiteralNode):
                return left

        return BinaryOpNode(left=left, operator=node.operator, right=right)

    def visit_static_member(self, node: StaticMemberAccessNode) -> ASTNode:
        full_type = TypeAcceleratorRegistry.resolve_full_type(node.type_name)
        member = node.member
        norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None

        # 1. [System.Convert]::ToInt32 / ToChar / FromBase64String
        if full_type == "System.Convert":
            if member.lower() == "toint32" and norm_args:
                val_node = norm_args[0]
                base_val = 10
                if len(norm_args) > 1 and isinstance(norm_args[1], NumberLiteralNode):
                    base_val = int(norm_args[1].value)
                if isinstance(val_node, (StringLiteralNode, NumberLiteralNode)):
                    try:
                        parsed = int(str(val_node.value).strip(), base_val)
                        return NumberLiteralNode(value=parsed, raw=str(parsed))
                    except ValueError:
                        pass
            elif member.lower() == "tochar" and norm_args:
                if isinstance(norm_args[0], NumberLiteralNode):
                    val = int(norm_args[0].value)
                    if 0 <= val <= 0x10FFFF:
                        return StringLiteralNode(value=chr(val), is_expandable=False)
            elif member.lower() == "frombase64string" and norm_args:
                if isinstance(norm_args[0], StringLiteralNode):
                    try:
                        b = base64.b64decode(norm_args[0].value)
                        byte_nodes = [NumberLiteralNode(value=x, raw=str(x)) for x in b]
                        zeroize_buffer(b)
                        return ArrayLiteralNode(elements=byte_nodes)
                    except Exception:
                        pass

        # 2. [System.String]::Join / Concat
        if full_type == "System.String":
            if member.lower() == "join" and norm_args and len(norm_args) >= 2:
                sep = norm_args[0].value if isinstance(norm_args[0], StringLiteralNode) else ""
                arr = norm_args[1]
                if isinstance(arr, ArrayLiteralNode):
                    return self._join_elements(arr.elements, delimiter=sep)
                if isinstance(arr, TypeCastNode) and TypeAcceleratorRegistry.get_canonical_alias(arr.type_name).lower() == "char[]":
                    char_arr = self._eval_char_array_cast(arr.expression)
                    if isinstance(char_arr, ArrayLiteralNode):
                        return self._join_elements(char_arr.elements, delimiter=sep)
            elif member.lower() == "concat" and norm_args:
                if all(isinstance(a, (StringLiteralNode, NumberLiteralNode)) for a in norm_args):
                    concat_str = "".join(str(a.value) for a in norm_args)
                    return StringLiteralNode(value=concat_str, is_expandable=False)

        # 3. [System.Type]::GetType
        if full_type == "System.Type" and member.lower() == "gettype" and norm_args:
            if isinstance(norm_args[0], StringLiteralNode):
                resolved = TypeAcceleratorRegistry.resolve_full_type(norm_args[0].value)
                return IdentifierNode(name=f"[{resolved}]")

        # 4. [System.Text.Encoding]::ASCII.GetString or similar composite static member
        if full_type == "System.Text.Encoding":
            parts = member.split(".", 1)
            if len(parts) == 2 and parts[1].lower() == "getstring" and norm_args:
                enc_name = parts[0].upper()
                byte_list = self._extract_integer_list(norm_args[0])
                if byte_list is not None:
                    raw_bytes = bytes([b & 0xFF for b in byte_list])
                    try:
                        if enc_name == "ASCII":
                            decoded = raw_bytes.decode("ascii", errors="replace")
                        elif enc_name in ("UTF8", "UTF-8"):
                            decoded = raw_bytes.decode("utf-8", errors="replace")
                        elif enc_name in ("UNICODE", "UTF16", "UTF-16"):
                            decoded = raw_bytes.decode("utf-16le", errors="replace")
                        else:
                            decoded = raw_bytes.decode("utf-8", errors="replace")
                        zeroize_buffer(raw_bytes)
                        return StringLiteralNode(value=decoded, is_expandable=False)
                    except Exception:
                        pass

        return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)

    def visit_method_call(self, node: MethodCallNode) -> ASTNode:
        target = self.visit(node.target)
        method_name = node.method_name
        norm_args = [self.visit(a) for a in node.arguments]

        # Check for [System.Text.Encoding]::ASCII.GetString([byte[]](...))
        if isinstance(target, StaticMemberAccessNode) and method_name.lower() == "getstring" and norm_args:
            full_type = TypeAcceleratorRegistry.resolve_full_type(target.type_name)
            if full_type == "System.Text.Encoding":
                enc_name = target.member.upper()
                byte_arg = norm_args[0]
                byte_list = self._extract_integer_list(byte_arg)
                if byte_list is not None:
                    raw_bytes = bytes([b & 0xFF for b in byte_list])
                    try:
                        if enc_name == "ASCII":
                            decoded = raw_bytes.decode("ascii", errors="replace")
                        elif enc_name in ("UTF8", "UTF-8"):
                            decoded = raw_bytes.decode("utf-8", errors="replace")
                        elif enc_name in ("UNICODE", "UTF16", "UTF-16"):
                            decoded = raw_bytes.decode("utf-16le", errors="replace")
                        else:
                            decoded = raw_bytes.decode("utf-8", errors="replace")
                        zeroize_buffer(raw_bytes)
                        return StringLiteralNode(value=decoded, is_expandable=False)
                    except Exception:
                        pass

        # Check for "string".GetType().Name
        if isinstance(target, MethodCallNode) and target.method_name.lower() == "gettype":
            if method_name.lower() == "name":
                if isinstance(target.target, StringLiteralNode):
                    return StringLiteralNode(value="String", is_expandable=False)

        return MethodCallNode(target=target, method_name=method_name, arguments=norm_args)

    def visit_member_access(self, node: MemberAccessNode) -> ASTNode:
        target = self.visit(node.target)
        member = node.member

        # Check type reflection: ([type]"System.String").Name or ([type]"System.String").FullName
        if isinstance(target, ParenthesizedExpressionNode):
            target = target.expression

        if isinstance(target, IdentifierNode) and target.name.startswith("[") and target.name.endswith("]"):
            metadata = TypeAcceleratorRegistry.get_type_metadata(target.name)
            if member in metadata:
                return StringLiteralNode(value=metadata[member], is_expandable=False)

        # String length: 'hello'.Length -> 5
        if isinstance(target, StringLiteralNode) and member.lower() == "length":
            val = len(target.value)
            return NumberLiteralNode(value=val, raw=str(val))

        return MemberAccessNode(target=target, member=member)

    def _join_elements(self, elements: List[ASTNode], delimiter: str = "") -> ASTNode:
        """Folds list of literal nodes into a single joined StringLiteralNode."""
        if all(isinstance(e, (StringLiteralNode, NumberLiteralNode)) for e in elements):
            joined_str = delimiter.join(str(e.value) for e in elements)
            return StringLiteralNode(value=joined_str, is_expandable=False)
        return ArrayLiteralNode(elements=elements)

    def _extract_index_list(self, node: ASTNode) -> Optional[List[int]]:
        """Extracts list of concrete integer indices from an index AST node."""
        if isinstance(node, NumberLiteralNode):
            return [int(node.value)]

        if isinstance(node, ArrayLiteralNode):
            result = []
            for e in node.elements:
                sub = self._extract_index_list(e)
                if sub is None:
                    return None
                result.extend(sub)
            return result

        if isinstance(node, RangeExpressionNode):
            s_list = self._extract_index_list(node.start)
            e_list = self._extract_index_list(node.end)
            if s_list and e_list:
                s = s_list[0]
                e = e_list[0]
                if s <= e:
                    return list(range(s, e + 1))
                else:
                    return list(range(s, e - 1, -1))

        return None

    def _extract_integer_list(self, node: ASTNode) -> Optional[List[int]]:
        """Extracts integers from ArrayLiteralNode, RangeExpressionNode, or ParenthesizedExpression."""
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_integer_list(node.expression)

        if isinstance(node, ArrayLiteralNode):
            result = []
            for e in node.elements:
                if isinstance(e, NumberLiteralNode):
                    result.append(int(e.value))
                elif isinstance(e, RangeExpressionNode):
                    sub = self._extract_integer_list(e)
                    if sub is None:
                        return None
                    result.extend(sub)
                else:
                    return None
            return result

        if isinstance(node, RangeExpressionNode):
            return self._extract_index_list(node)

        if isinstance(node, NumberLiteralNode):
            return [int(node.value)]

        return None
