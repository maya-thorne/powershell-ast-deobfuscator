"""
Unit and integration tests for PowerShell arithmetic and bitwise static folding engine.
"""

import unittest

from src.bitwise_folding_engine import PowerShellBitwiseFoldingEngine
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser


class TestBitwiseFoldingEngine(unittest.TestCase):
    """Test suite for PowerShellBitwiseFoldingEngine."""

    def _fold(self, code: str) -> str:
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        folder = PowerShellBitwiseFoldingEngine()
        folded_ast = folder.fold(ast)
        normalizer = PowerShellNormalizer()
        return normalizer.to_source(folded_ast).strip()

    def test_bitwise_xor_literal(self):
        # 0x56 (86) ^ 0x33 (51) = 101 (0x65)
        res = self._fold("0x56 -bxor 0x33")
        self.assertEqual(res, "101")

    def test_bitwise_and_literal(self):
        # 0xFF & 0x0F = 15
        res = self._fold("0xFF -band 0x0F")
        self.assertEqual(res, "15")

    def test_bitwise_or_literal(self):
        # 0x10 | 0x01 = 17
        res = self._fold("0x10 -bor 0x01")
        self.assertEqual(res, "17")

    def test_shift_left(self):
        # 1 << 4 = 16
        res = self._fold("1 -shl 4")
        self.assertEqual(res, "16")

    def test_shift_right(self):
        # 64 >> 2 = 16
        res = self._fold("64 -shr 2")
        self.assertEqual(res, "16")

    def test_bitwise_not(self):
        # ~0 = -1, ~(-1) = 0, ~5 = -6
        res0 = self._fold("-bnot 0")
        self.assertEqual(res0, "-1")
        res1 = self._fold("-bnot -1")
        self.assertEqual(res1, "0")
        res5 = self._fold("-bnot 5")
        self.assertEqual(res5, "-6")

    def test_basic_arithmetic(self):
        self.assertEqual(self._fold("10 + 20"), "30")
        self.assertEqual(self._fold("50 - 18"), "32")
        self.assertEqual(self._fold("6 * 7"), "42")
        self.assertEqual(self._fold("100 / 4"), "25")
        self.assertEqual(self._fold("17 % 5"), "2")

    def test_arithmetic_precedence(self):
        # Multiplication before addition: 2 + (3 * 4) = 14
        self.assertEqual(self._fold("2 + 3 * 4"), "14")
        # Division before subtraction: 20 - (10 / 2) = 15
        self.assertEqual(self._fold("20 - 10 / 2"), "15")
        # Parentheses override precedence: (2 + 3) * 4 = 20
        self.assertEqual(self._fold("(2 + 3) * 4"), "20")

    def test_chained_bitwise_and_arithmetic(self):
        # ((0x20 ^ 0x05) << 2) + 1 = (37 << 2) + 1 = 148 + 1 = 149
        self.assertEqual(self._fold("((0x20 -bxor 0x05) -shl 2) + 1"), "149")

    def test_char_type_cast_folding(self):
        # [char](0x41 ^ 0x20) = [char]0x61 = 'a'
        res = self._fold("[char](0x41 -bxor 0x20)")
        self.assertEqual(res, "'a'")

    def test_byte_type_cast_folding(self):
        # [byte](0x1234 & 0xFF) = [byte]0x34 = 52
        res = self._fold("[byte](0x1234 -band 0xFF)")
        self.assertEqual(res, "52")

    def test_char_array_cast_folding(self):
        # [char](65 + 8) = 'I'
        res = self._fold("[char](65 + 8)")
        self.assertEqual(res, "'I'")

    def test_division_by_zero_safety(self):
        # Should not crash on division by zero; leave AST node intact
        res = self._fold("10 / 0")
        self.assertEqual(res, "10 / 0")
        res_mod = self._fold("10 % 0")
        self.assertEqual(res_mod, "10 % 0")

    def test_excessive_shift_safety(self):
        # Shifts > 64 or negative shifts should not crash or overflow
        res_large = self._fold("1 -shl 100")
        self.assertEqual(res_large, "1 -shl 100")

    def test_comparison_folding(self):
        self.assertEqual(self._fold("10 -gt 5"), "$true")
        self.assertEqual(self._fold("10 -lt 5"), "$false")
        self.assertEqual(self._fold("42 -eq 42"), "$true")
        self.assertEqual(self._fold("42 -ne 42"), "$false")

    def test_logical_not_folding(self):
        self.assertEqual(self._fold("-not $true"), "$false")
        self.assertEqual(self._fold("!$false"), "$true")
        self.assertEqual(self._fold("-not 0"), "$true")
        self.assertEqual(self._fold("-not 1"), "$false")

    def test_symbol_propagation_in_bitwise_expressions(self):
        tokens = PowerShellLexer("$key = 0x33; $val = 0x56; $res = $val -bxor $key").tokenize()
        ast = PowerShellParser(tokens).parse()
        symbols = {}
        folder = PowerShellBitwiseFoldingEngine(symbols=symbols)
        folded = folder.fold(ast)
        normalizer = PowerShellNormalizer(symbols=symbols)
        code = normalizer.to_source(folded)
        self.assertIn("$res = 101", code)

    def test_deobfuscator_integration(self):
        engine = PowerShellDeobfuscator()
        script = "$cmd = [char](0x41 -bxor 0x20) + [char](100 + 1) + [char](99 - 0); & $cmd"
        deobf = engine.deobfuscate(script)
        self.assertIn("aec", deobf)


if __name__ == "__main__":
    unittest.main()
