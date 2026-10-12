"""Unit tests for token definitions and data structures."""

import unittest
from src.tokens import Token, TokenType


class TestTokens(unittest.TestCase):
    def test_token_creation(self):
        tok = Token(TokenType.IDENTIFIER, "Get-Process", 1, 1)
        self.assertEqual(tok.type, TokenType.IDENTIFIER)
        self.assertEqual(tok.value, "Get-Process")
        self.assertEqual(tok.line, 1)
        self.assertEqual(tok.column, 1)

    def test_token_repr(self):
        tok = Token(TokenType.STRING_LITERAL, "test", 2, 5)
        self.assertIn("STRING_LITERAL", repr(tok))
        self.assertIn("'test'", repr(tok))


if __name__ == "__main__":
    unittest.main()
