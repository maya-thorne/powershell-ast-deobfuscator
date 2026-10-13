"""
Unit and integration tests for PowerShell AST pipeline optimizer.
Validates Foreach-Object (% / foreach), Select-Object (select), Where-Object (? / where),
Out-String, pipeline chaining, and command simplification.
"""

import unittest

from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser
from src.pipeline_optimizer import PowerShellPipelineOptimizer


class TestPipelineOptimizer(unittest.TestCase):
    """
    Test suite for pipeline stage reduction and static collection evaluation.
    """

    def _parse_and_optimize(self, code: str) -> str:
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        normalizer = PowerShellNormalizer()
        norm_ast = normalizer.normalize(ast)
        return normalizer.to_source(norm_ast)

    def test_foreach_char_array_conversion(self):
        code = "@(105, 101, 120) | % { [char]$_ }"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@('i', 'e', 'x')")

    def test_foreach_bare_comma_pipeline(self):
        code = "105, 101, 120 | % { [char]$_ }"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@('i', 'e', 'x')")

    def test_foreach_join_reduction(self):
        code = "(105, 101, 120 | % { [char]$_ }) -join ''"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "'iex'")

    def test_foreach_range_expression(self):
        code = "65..67 | % { [char]$_ }"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@('A', 'B', 'C')")

    def test_foreach_bitwise_xor(self):
        code = "@(0x56, 0x5a, 0x47) | % { $_ -bxor 0x33 }"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@(101, 105, 116)")

    def test_foreach_arithmetic_offset(self):
        code = "@(10, 20, 30) | % { $_ + 5 }"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@(15, 25, 35)")

    def test_foreach_string_methods(self):
        code_trim = "@('  foo  ', '  bar  ') | % { $_.Trim() }"
        self.assertEqual(self._parse_and_optimize(code_trim), "@('foo', 'bar')")

        code_upper = "@('iex', 'calc') | % { $_.ToUpper() }"
        self.assertEqual(self._parse_and_optimize(code_upper), "@('IEX', 'CALC')")

        code_replace = "@('apple', 'apricot') | % { $_.Replace('ap', 'X') }"
        self.assertEqual(self._parse_and_optimize(code_replace), "@('Xple', 'Xricot')")

        code_sub = "@('powershell', 'malware') | % { $_.Substring(0, 5) }"
        self.assertEqual(self._parse_and_optimize(code_sub), "@('power', 'malwa')")

    def test_foreach_property_mapping(self):
        code = "@('alpha', 'beta', 'gamma') | % Length"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@(5, 4, 5)")

    def test_select_first_and_last(self):
        code_first = "@(10, 20, 30, 40) | select -First 2"
        self.assertEqual(self._parse_and_optimize(code_first), "@(10, 20)")

        code_last = "@(10, 20, 30, 40) | select -Last 2"
        self.assertEqual(self._parse_and_optimize(code_last), "@(30, 40)")

    def test_select_skip_and_index(self):
        code_skip = "@(10, 20, 30, 40) | select -Skip 2"
        self.assertEqual(self._parse_and_optimize(code_skip), "@(30, 40)")

        code_idx = "@(10, 20, 30, 40) | select -Index 2"
        self.assertEqual(self._parse_and_optimize(code_idx), "30")

    def test_select_unique(self):
        code = "@(1, 2, 2, 3, 1, 4) | select -Unique"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@(1, 2, 3, 4)")

    def test_select_expand_property(self):
        code = "@('hello', 'powershell') | select -ExpandProperty Length"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@(5, 10)")

    def test_where_object_comparison(self):
        code_gt = "@(1, 5, 10, 15) | ? { $_ -gt 5 }"
        self.assertEqual(self._parse_and_optimize(code_gt), "@(10, 15)")

        code_ne = "@(1, 2, 3) | ? { $_ -ne 2 }"
        self.assertEqual(self._parse_and_optimize(code_ne), "@(1, 3)")

    def test_where_object_wildcard_like(self):
        code = "@('cat', 'dog', 'cow', 'deer') | where { $_ -like 'c*' }"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@('cat', 'cow')")

    def test_out_string_folding(self):
        code = "@('line1', 'line2') | Out-String"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "'line1\r\nline2'")

    def test_piped_iex_simplification(self):
        code = "'calc.exe' | iex"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_chained_pipeline_stages(self):
        code = "@(100, 101, 102, 103) | select -First 2 | % { [char]$_ }"
        result = self._parse_and_optimize(code)
        self.assertEqual(result, "@('d', 'e')")

    def test_end_to_end_pipeline_deobfuscation(self):
        engine = PowerShellDeobfuscator()
        obfuscated = "((105, 101, 120 | % { [char]$_ }) -join '') | iex"
        result = engine.deobfuscate(obfuscated)
        self.assertEqual(result, "iex 'iex'")


if __name__ == "__main__":
    unittest.main()
