"""Unit tests for PowerShell Lexer."""

import unittest
from src.lexer import PowerShellLexer
from src.tokens import TokenType


class TestPowerShellLexer(unittest.TestCase):
    def test_single_quoted_string(self):
        code = "'Hello World'"
        tokens = PowerShellLexer(code).tokenize()
        self.assertEqual(tokens[0].type, TokenType.STRING_LITERAL)
        self.assertEqual(tokens[0].value, "Hello World")

    def test_double_quoted_string_with_backtick(self):
        code = '"He`llo `tWorld"'
        tokens = PowerShellLexer(code).tokenize()
        self.assertEqual(tokens[0].type, TokenType.STRING_LITERAL)
        self.assertEqual(tokens[0].value, "Hello \tWorld")

    def test_backtick_in_identifier(self):
        code = "In`voke-Exp`ression"
        tokens = PowerShellLexer(code).tokenize()
        self.assertEqual(tokens[0].type, TokenType.IDENTIFIER)
        self.assertEqual(tokens[0].value, "Invoke-Expression")

    def test_variables(self):
        code = "$target $env:APPDATA ${my_custom_var}"
        tokens = PowerShellLexer(code).tokenize()
        self.assertEqual(tokens[0].type, TokenType.VARIABLE)
        self.assertEqual(tokens[0].value, "target")
        self.assertEqual(tokens[1].type, TokenType.VARIABLE)
        self.assertEqual(tokens[1].value, "env:APPDATA")
        self.assertEqual(tokens[2].type, TokenType.VARIABLE)
        self.assertEqual(tokens[2].value, "my_custom_var")

    def test_format_operator(self):
        code = "'{0}' -f 'test'"
        tokens = PowerShellLexer(code).tokenize()
        self.assertEqual(tokens[0].type, TokenType.STRING_LITERAL)
        self.assertEqual(tokens[1].type, TokenType.OP_FORMAT)
        self.assertEqual(tokens[2].type, TokenType.STRING_LITERAL)

    def test_numbers(self):
        code = "42 0x2A"
        tokens = PowerShellLexer(code).tokenize()
        self.assertEqual(tokens[0].type, TokenType.NUMBER_LITERAL)
        self.assertEqual(tokens[0].value, "42")
        self.assertEqual(tokens[1].type, TokenType.NUMBER_LITERAL)
        self.assertEqual(tokens[1].value, "42")

    def test_comments_stripping(self):
        code = "# Single line\n$x = 1 <# block comment #>; $y = 2"
        tokens = PowerShellLexer(code).tokenize()
        var_names = [t.value for t in tokens if t.type == TokenType.VARIABLE]
        self.assertEqual(var_names, ["x", "y"])


if __name__ == "__main__":
    unittest.main()
