"""
Unit and integration tests for PowerShell Subexpression Unwrapper.
Validates subexpression unboxing, nested unwrapping, string concatenation folding,
multi-statement evaluation, and expandable string interpolation.
"""

import unittest

from src.ast_nodes import (
    CommandNode,
    IdentifierNode,
    NumberLiteralNode,
    StringLiteralNode,
    SubexpressionNode,
)
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser
from src.subexpression_unwrapper import PowerShellSubexpressionUnwrapper


class TestPowerShellSubexpressionUnwrapper(unittest.TestCase):
    """Test suite for subexpression ($(...)) unboxing and reduction."""

    def setUp(self):
        self.unwrapper = PowerShellSubexpressionUnwrapper()
        self.normalizer = PowerShellNormalizer()
        self.deobfuscator = PowerShellDeobfuscator()

    def _parse_and_unwrap(self, code: str) -> str:
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        norm_ast = self.normalizer.normalize(ast)
        return self.normalizer.to_source(norm_ast)

    def test_simple_subexpression_unboxing(self):
        code = "$('calc.exe')"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'calc.exe'")

    def test_redundant_nested_subexpressions_double(self):
        code = "$(( 'cmd.exe' ))"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'cmd.exe'")

    def test_redundant_nested_subexpressions_triple(self):
        code = "$((('cmd.exe')))"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'cmd.exe'")

    def test_subexpression_string_concatenation(self):
        code = "$('i') + $('e') + $('x')"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'iex'")

    def test_subexpression_with_variable_statement(self):
        code = "$($x = 'calc'; $x)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'calc'")

    def test_subexpression_with_multiple_variable_statements(self):
        code = "$($a = 'foo'; $b = 'bar'; $a + $b)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'foobar'")

    def test_expandable_string_interpolation_subexpressions(self):
        code = '"$(\'Invoke\')-$(\'Expression\')"'
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'Invoke-Expression'")

    def test_expandable_string_interpolation_concatenation(self):
        code = '"$(\'In\' + \'voke\')-$(\'Ex\' + \'pression\')"'
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'Invoke-Expression'")

    def test_expandable_string_prefix_suffix(self):
        code = '"prefix $( \'foo\' ) suffix"'
        result = self._parse_and_unwrap(code)
        self.assertIn("prefix foo suffix", result)

    def test_array_indexing_off_subexpression(self):
        code = "$('hello')[1]"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'e'")

    def test_array_indexing_off_array_subexpression(self):
        code = "$(10, 20, 30)[2]"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "30")

    def test_complex_pipeline_inside_subexpression(self):
        code = "$( (73, 69, 88 | % { [char]$_ }) -join '' )"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'IEX'")

    def test_multi_statement_preservation_non_trivial(self):
        code = "$(Start-Process calc; Wait-Process $p; Get-Process)"
        result = self._parse_and_unwrap(code)
        self.assertTrue(result.startswith("$(") and result.endswith(")"))
        self.assertIn("Start-Process", result)
        self.assertIn("Wait-Process", result)

    def test_subexpression_as_command_argument(self):
        code = "iex $( 'calc.exe' )"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_subexpression_as_command_target(self):
        code = "$( 'Get-Process' )"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'Get-Process'")

    def test_subexpression_numeric_literal(self):
        code = "$($((100)))"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "100")

    def test_subexpression_typecast_evaluation(self):
        code = "$([char]65)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'A'")

    def test_empty_subexpression_unboxing(self):
        code = "$()"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "''")

    def test_deobfuscator_engine_convergence_subexpression(self):
        code = "$cmd = $('i') + $('e') + $('x'); & $cmd $( 'calc.exe' )"
        result = self.deobfuscator.deobfuscate(code)
        self.assertIn("iex 'calc.exe'", result)


if __name__ == "__main__":
    unittest.main()
