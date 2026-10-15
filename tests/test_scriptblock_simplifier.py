"""
Unit and integration tests for PowerShell AST ScriptBlock and control flow simplifier.
Validates & { ... }, . { ... }, { ... }.Invoke(), trivial conditional folding (if $true/$false),
comparison evaluations, and dead loop elimination.
"""

import unittest

from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser
from src.scriptblock_simplifier import PowerShellScriptBlockSimplifier


class TestScriptBlockSimplifier(unittest.TestCase):
    """
    Test suite for ScriptBlock unwrapping, condition evaluation, and dead code elimination.
    """

    def _parse_and_simplify(self, code: str) -> str:
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        normalizer = PowerShellNormalizer(unwrap_iex=False)
        norm_ast = normalizer.normalize(ast)
        return normalizer.to_source(norm_ast)

    def test_call_operator_scriptblock_unwrapping(self):
        code = "& { iex 'calc.exe' }"
        result = self._parse_and_simplify(code)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_call_operator_with_arguments(self):
        code = "& { iex } 'calc.exe'"
        result = self._parse_and_simplify(code)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_dot_source_scriptblock_unwrapping(self):
        code = ". { iex 'calc.exe' }"
        result = self._parse_and_simplify(code)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_scriptblock_invoke_method_unwrapping(self):
        code = "{ iex 'calc.exe' }.Invoke()"
        result = self._parse_and_simplify(code)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_parenthesized_scriptblock_invoke(self):
        code = "({ iex 'calc.exe' }).Invoke()"
        result = self._parse_and_simplify(code)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_scriptblock_variable_tracking(self):
        code = "$sb = { iex 'calc.exe' }; &$sb"
        result = self._parse_and_simplify(code)
        self.assertIn("iex 'calc.exe'", result)

    def test_if_true_branch_reduction(self):
        code = "if ($true) { iex 'calc.exe' } else { Write-Host 'decoy' }"
        result = self._parse_and_simplify(code)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_if_numeric_truthiness(self):
        code_nonzero = "if (1) { iex 'calc.exe' }"
        self.assertEqual(self._parse_and_simplify(code_nonzero), "iex 'calc.exe'")

        code_zero = "if (0) { Write-Host 'decoy' } else { iex 'calc.exe' }"
        self.assertEqual(self._parse_and_simplify(code_zero), "iex 'calc.exe'")

    def test_if_string_truthiness(self):
        code_nonempty = "if ('active') { iex 'calc.exe' }"
        self.assertEqual(self._parse_and_simplify(code_nonempty), "iex 'calc.exe'")

        code_empty = "if ('') { Write-Host 'decoy' } else { iex 'calc.exe' }"
        self.assertEqual(self._parse_and_simplify(code_empty), "iex 'calc.exe'")

    def test_if_false_branch_reduction(self):
        code = "if ($false) { Write-Host 'decoy' } else { iex 'calc.exe' }"
        result = self._parse_and_simplify(code)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_if_false_dead_code_elimination(self):
        code = "$a = 1; if ($false) { Write-Host 'decoy' }; $b = 2"
        result = self._parse_and_simplify(code)
        self.assertEqual(result, "$a = 1\n$b = 2")

    def test_if_comparison_operators(self):
        code_eq = "if (1 -eq 1) { iex 'calc.exe' } else { 'decoy' }"
        self.assertEqual(self._parse_and_simplify(code_eq), "iex 'calc.exe'")

        code_ne = "if ('a' -ne 'a') { 'decoy' } else { iex 'calc.exe' }"
        self.assertEqual(self._parse_and_simplify(code_ne), "iex 'calc.exe'")

        code_gt = "if (10 -gt 5) { iex 'calc.exe' }"
        self.assertEqual(self._parse_and_simplify(code_gt), "iex 'calc.exe'")

        code_lt = "if (10 -lt 5) { 'decoy' } else { iex 'calc.exe' }"
        self.assertEqual(self._parse_and_simplify(code_lt), "iex 'calc.exe'")

    def test_if_unary_negation(self):
        code_not_false = "if (!($false)) { iex 'calc.exe' }"
        self.assertEqual(self._parse_and_simplify(code_not_false), "iex 'calc.exe'")

        code_not_true = "if (-not $true) { 'decoy' } else { iex 'calc.exe' }"
        self.assertEqual(self._parse_and_simplify(code_not_true), "iex 'calc.exe'")

    def test_while_false_dead_code_elimination(self):
        code = "$x = 10; while ($false) { Write-Host 'infinite' }; $y = 20"
        result = self._parse_and_simplify(code)
        self.assertEqual(result, "$x = 10\n$y = 20")

    def test_complex_end_to_end_decoy_unwrapping(self):
        engine = PowerShellDeobfuscator(unwrap_iex=False)
        obfuscated = """
        if ($true) {
            & { (105, 101, 120 | % { [char]$_ }) -join '' } 'calc.exe'
        } else {
            Write-Host 'decoy evasion'
        }
        """
        result = engine.deobfuscate(obfuscated)
        self.assertEqual(result, "iex 'calc.exe'")


if __name__ == "__main__":
    unittest.main()
