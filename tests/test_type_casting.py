"""
Unit and integration tests for PowerShell Type Accelerators, Type Casting,
Array Shuffling, Reverse Slices, and -join Operation Resolvers.
"""

import unittest

from src.ast_nodes import (
    ArrayLiteralNode,
    BinaryOpNode,
    IndexAccessNode,
    NumberLiteralNode,
    RangeExpressionNode,
    StringLiteralNode,
    TypeCastNode,
    UnaryOpNode,
)
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser
from src.type_accelerators import TypeAcceleratorRegistry
from src.type_casting_resolver import PowerShellTypeCastingResolver


class TestTypeAcceleratorRegistry(unittest.TestCase):
    """Verifies type accelerator lookup, case insensitivity, and canonical aliases."""

    def test_lookup_and_normalization(self):
        self.assertTrue(TypeAcceleratorRegistry.is_type_accelerator("char"))
        self.assertTrue(TypeAcceleratorRegistry.is_type_accelerator("cHaR[]"))
        self.assertTrue(TypeAcceleratorRegistry.is_type_accelerator("[int]"))
        self.assertTrue(TypeAcceleratorRegistry.is_type_accelerator("BYTE[]"))
        self.assertTrue(TypeAcceleratorRegistry.is_type_accelerator("convert"))
        self.assertTrue(TypeAcceleratorRegistry.is_type_accelerator("regex"))

        self.assertEqual(TypeAcceleratorRegistry.resolve_full_type("char"), "System.Char")
        self.assertEqual(TypeAcceleratorRegistry.resolve_full_type("[char[]]"), "System.Char[]")
        self.assertEqual(TypeAcceleratorRegistry.resolve_full_type("int"), "System.Int32")
        self.assertEqual(TypeAcceleratorRegistry.resolve_full_type("byte[]"), "System.Byte[]")
        self.assertEqual(TypeAcceleratorRegistry.resolve_full_type("convert"), "System.Convert")

    def test_canonical_alias(self):
        self.assertEqual(TypeAcceleratorRegistry.get_canonical_alias("System.Char"), "char")
        self.assertEqual(TypeAcceleratorRegistry.get_canonical_alias("[System.Char[]]"), "char[]")
        self.assertEqual(TypeAcceleratorRegistry.get_canonical_alias("cHaR"), "char")
        self.assertEqual(TypeAcceleratorRegistry.get_canonical_alias("bYtE[]"), "byte[]")

    def test_type_metadata(self):
        meta = TypeAcceleratorRegistry.get_type_metadata("string")
        self.assertEqual(meta["Name"], "String")
        self.assertEqual(meta["FullName"], "System.String")
        self.assertEqual(meta["Namespace"], "System")


class TestTypeCastingResolver(unittest.TestCase):
    """Verifies AST reduction of type casts and array manipulations."""

    def setUp(self):
        self.resolver = PowerShellTypeCastingResolver()

    def test_char_and_int_evaluations(self):
        # [char]65 -> 'A'
        node_char_65 = TypeCastNode(type_name="char", expression=NumberLiteralNode(value=65, raw="65"))
        res = self.resolver.resolve(node_char_65)
        self.assertIsInstance(res, StringLiteralNode)
        self.assertEqual(res.value, "A")

        # [char]'0x41' -> 'A'
        node_char_hex = TypeCastNode(type_name="char", expression=StringLiteralNode(value="0x41"))
        res = self.resolver.resolve(node_char_hex)
        self.assertIsInstance(res, StringLiteralNode)
        self.assertEqual(res.value, "A")

        # [int]'42' -> 42
        node_int = TypeCastNode(type_name="int", expression=StringLiteralNode(value="42"))
        res = self.resolver.resolve(node_int)
        self.assertIsInstance(res, NumberLiteralNode)
        self.assertEqual(res.value, 42)

        # [byte]258 -> 2
        node_byte = TypeCastNode(type_name="byte", expression=NumberLiteralNode(value=258, raw="258"))
        res = self.resolver.resolve(node_byte)
        self.assertIsInstance(res, NumberLiteralNode)
        self.assertEqual(res.value, 2)

    def test_char_array_to_string_cast(self):
        # [char[]](73, 69, 88) -> ['I', 'E', 'X']
        arr_node = ArrayLiteralNode(elements=[
            NumberLiteralNode(73, "73"),
            NumberLiteralNode(69, "69"),
            NumberLiteralNode(88, "88"),
        ])
        char_arr_cast = TypeCastNode(type_name="char[]", expression=arr_node)
        str_cast = TypeCastNode(type_name="string", expression=char_arr_cast)
        res = self.resolver.resolve(str_cast)
        self.assertIsInstance(res, StringLiteralNode)
        self.assertEqual(res.value, "IEX")

    def test_unary_join_char_array(self):
        # -join ('h', 'e', 'l', 'l', 'o') -> 'hello'
        arr = ArrayLiteralNode(elements=[
            StringLiteralNode("h"),
            StringLiteralNode("e"),
            StringLiteralNode("l"),
            StringLiteralNode("l"),
            StringLiteralNode("o"),
        ])
        unary_node = UnaryOpNode(operator="-join", operand=arr)
        res = self.resolver.resolve(unary_node)
        self.assertIsInstance(res, StringLiteralNode)
        self.assertEqual(res.value, "hello")

    def test_binary_join_with_delimiter(self):
        # (1, 2, 3) -join '-' -> '1-2-3'
        arr = ArrayLiteralNode(elements=[
            NumberLiteralNode(1, "1"),
            NumberLiteralNode(2, "2"),
            NumberLiteralNode(3, "3"),
        ])
        bin_join = BinaryOpNode(left=arr, operator="-join", right=StringLiteralNode("-"))
        res = self.resolver.resolve(bin_join)
        self.assertIsInstance(res, StringLiteralNode)
        self.assertEqual(res.value, "1-2-3")

    def test_array_indexing_and_shuffling(self):
        # 'hello'[1] -> 'e'
        idx_single = IndexAccessNode(target=StringLiteralNode("hello"), index=NumberLiteralNode(1, "1"))
        res = self.resolver.resolve(idx_single)
        self.assertIsInstance(res, StringLiteralNode)
        self.assertEqual(res.value, "e")

        # 'xesi'[3, 0, 1, 2] -> ['i', 'x', 'e', 's']
        indices = ArrayLiteralNode(elements=[
            NumberLiteralNode(3, "3"),
            NumberLiteralNode(0, "0"),
            NumberLiteralNode(1, "1"),
            NumberLiteralNode(2, "2"),
        ])
        idx_multi = IndexAccessNode(target=StringLiteralNode("xesi"), index=indices)
        res = self.resolver.resolve(idx_multi)
        self.assertIsInstance(res, ArrayLiteralNode)
        joined = self.resolver.resolve(UnaryOpNode(operator="-join", operand=res))
        self.assertIsInstance(joined, StringLiteralNode)
        self.assertEqual(joined.value, "ixes")

    def test_reverse_range_slicing(self):
        # 'olleh'[4..0] -> ['h', 'e', 'l', 'l', 'o']
        rng = RangeExpressionNode(start=NumberLiteralNode(4, "4"), end=NumberLiteralNode(0, "0"))
        idx_range = IndexAccessNode(target=StringLiteralNode("olleh"), index=rng)
        res = self.resolver.resolve(idx_range)
        self.assertIsInstance(res, ArrayLiteralNode)
        joined = self.resolver.resolve(UnaryOpNode(operator="-join", operand=res))
        self.assertIsInstance(joined, StringLiteralNode)
        self.assertEqual(joined.value, "hello")

    def test_negative_reverse_range_slicing(self):
        # 'olleh'[-1..-5] -> ['h', 'e', 'l', 'l', 'o']
        rng = RangeExpressionNode(start=NumberLiteralNode(-1, "-1"), end=NumberLiteralNode(-5, "-5"))
        idx_range = IndexAccessNode(target=StringLiteralNode("olleh"), index=rng)
        res = self.resolver.resolve(idx_range)
        self.assertIsInstance(res, ArrayLiteralNode)
        joined = self.resolver.resolve(UnaryOpNode(operator="-join", operand=res))
        self.assertIsInstance(joined, StringLiteralNode)
        self.assertEqual(joined.value, "hello")


class TestPowerShellEndToEndDeobfuscation(unittest.TestCase):
    """End-to-end integration tests using full parser, normalizer, and deobfuscator."""

    def setUp(self):
        self.deobfuscator = PowerShellDeobfuscator()

    def test_char_concatenation_folding(self):
        code = "[char]105 + [char]101 + [char]120"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'iex'")

    def test_chained_hex_char_casting(self):
        code = "[char][int]'0x49' + [char][int]'0x45' + [char][int]'0x58'"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'IEX'")

    def test_char_array_string_cast_folding(self):
        code = "[string][char[]](73, 69, 88)"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'IEX'")

    def test_unary_join_char_array(self):
        code = "-join [char[]](73, 69, 88)"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'IEX'")

    def test_binary_join_char_array(self):
        code = "[char[]](73, 69, 88) -join ''"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'IEX'")

    def test_shuffled_char_array_indexing_join(self):
        code = "[char[]](88, 69, 73)[2, 1, 0] -join ''"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'IEX'")

    def test_reverse_range_slice_script(self):
        code = "('olleh')[4..0] -join ''"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'hello'")

    def test_negative_range_slice_script(self):
        code = "('olleh')[-1..-5] -join ''"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'hello'")

    def test_encoding_get_string_ascii(self):
        code = "[System.Text.Encoding]::ASCII.GetString([byte[]](73, 69, 88))"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'IEX'")

    def test_encoding_get_string_utf8(self):
        code = "[Text.Encoding]::UTF8.GetString([byte[]](104, 101, 108, 108, 111))"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'hello'")

    def test_convert_static_methods(self):
        code = "[Convert]::ToInt32('49', 16)"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "73")

        code_char = "[Convert]::ToChar(73)"
        result_char = self.deobfuscator.deobfuscate(code_char)
        self.assertEqual(result_char, "'I'")

    def test_string_static_join_and_concat(self):
        code_join = "[string]::Join('', [char[]](73, 69, 88))"
        res_join = self.deobfuscator.deobfuscate(code_join)
        self.assertEqual(res_join, "'IEX'")

        code_concat = "[string]::Concat([char]73, [char]69, [char]88)"
        res_concat = self.deobfuscator.deobfuscate(code_concat)
        self.assertEqual(res_concat, "'IEX'")

    def test_type_reflection_member_access(self):
        code = "([type]'System.String').Name"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'String'")

        code_full = "([type]'System.String').FullName"
        result_full = self.deobfuscator.deobfuscate(code_full)
        self.assertEqual(result_full, "'System.String'")

    def test_complex_multi_layer_obfuscation(self):
        # Combines format operator -f, char casting, and string concatenation
        code = "('{0}{1}' -f [char]105, [char]101) + [char]120"
        result = self.deobfuscator.deobfuscate(code)
        self.assertEqual(result, "'iex'")


if __name__ == "__main__":
    unittest.main()
