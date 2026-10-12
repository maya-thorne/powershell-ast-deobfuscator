"""Unit tests for PowerShell AST Parser."""

import unittest
from src.ast_nodes import (
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
    FormatOpNode,
    PipelineNode,
    StringLiteralNode,
    VariableNode,
)
from src.lexer import PowerShellLexer
from src.parser import PowerShellParser


class TestPowerShellParser(unittest.TestCase):
    def test_parse_assignment(self):
        code = "$url = 'http://example.com'"
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        self.assertEqual(len(ast.statements), 1)
        stmt = ast.statements[0]
        self.assertIsInstance(stmt, AssignmentNode)
        self.assertEqual(stmt.variable.name, "url")
        self.assertIsInstance(stmt.expression, StringLiteralNode)
        self.assertEqual(stmt.expression.value, "http://example.com")

    def test_parse_format_op(self):
        code = "'{1}{0}' -f 'World', 'Hello '"
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        stmt = ast.statements[0]
        self.assertIsInstance(stmt, FormatOpNode)
        self.assertEqual(stmt.format_string.value, "{1}{0}")
        self.assertEqual(len(stmt.arguments), 2)
        self.assertEqual(stmt.arguments[0].value, "World")
        self.assertEqual(stmt.arguments[1].value, "Hello ")

    def test_parse_pipeline(self):
        code = "Get-Service | Where-Object"
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        stmt = ast.statements[0]
        self.assertIsInstance(stmt, PipelineNode)
        self.assertEqual(len(stmt.elements), 2)

    def test_parse_binary_concatenation(self):
        code = "'Down' + 'load' + 'String'"
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        stmt = ast.statements[0]
        self.assertIsInstance(stmt, BinaryOpNode)
        self.assertEqual(stmt.operator, "+")


if __name__ == "__main__":
    unittest.main()
