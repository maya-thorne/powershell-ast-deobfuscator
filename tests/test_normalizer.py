"""Unit tests for PowerShell AST Normalizer."""

import unittest
from src.ast_nodes import StringLiteralNode
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser


class TestPowerShellNormalizer(unittest.TestCase):
    def test_fold_string_concatenation(self):
        code = "'Down' + 'load' + 'String'"
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        normalizer = PowerShellNormalizer()
        norm_ast = normalizer.normalize(ast)
        stmt = norm_ast.statements[0]
        self.assertIsInstance(stmt, StringLiteralNode)
        self.assertEqual(stmt.value, "DownloadString")

    def test_fold_format_operator(self):
        code = "'{1}{0}' -f 'World', 'Hello '"
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        normalizer = PowerShellNormalizer()
        norm_ast = normalizer.normalize(ast)
        stmt = norm_ast.statements[0]
        self.assertIsInstance(stmt, StringLiteralNode)
        self.assertEqual(stmt.value, "Hello World")

    def test_to_source_serialization(self):
        code = "$cmd = 'calc.exe'"
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        normalizer = PowerShellNormalizer()
        norm_ast = normalizer.normalize(ast)
        src = normalizer.to_source(norm_ast)
        self.assertEqual(src, "$cmd = 'calc.exe'")


if __name__ == "__main__":
    unittest.main()
