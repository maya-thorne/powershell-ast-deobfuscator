"""
Unit and integration tests for PowerShell Reflection & Dynamic Member Unwrapper.
Verifies .Invoke(), ::Invoke(), GetMethod(), GetProperty(), GetField(),
dynamic member access, pure .NET string & math constant folding, and multi-pass convergence.
"""

import unittest

from src.ast_nodes import (
    CommandNode,
    IdentifierNode,
    MethodCallNode,
    NumberLiteralNode,
    StaticMemberAccessNode,
    StringLiteralNode,
)
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser
from src.reflection_unwrapper import PowerShellReflectionUnwrapper


class TestReflectionUnwrapper(unittest.TestCase):
    """Unit tests for PowerShellReflectionUnwrapper AST transformations."""

    def setUp(self):
        self.unwrapper = PowerShellReflectionUnwrapper()
        self.normalizer = PowerShellNormalizer()
        self.deobfuscator = PowerShellDeobfuscator()

    def _parse_and_unwrap(self, code: str):
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        norm_ast = self.normalizer.normalize(ast)
        return self.normalizer.to_source(norm_ast)

    def test_static_getmethod_invoke_basic(self):
        code = "[System.IO.File].GetMethod('ReadAllText').Invoke($null, @('C:\\test.txt'))"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "[System.IO.File]::ReadAllText('C:\\test.txt')")

    def test_static_getmethod_invoke_empty_args(self):
        code = "[System.Reflection.Assembly].GetMethod('GetExecutingAssembly').Invoke($null, @())"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "[System.Reflection.Assembly]::GetExecutingAssembly()")

    def test_instance_getmethod_invoke(self):
        code = "$wc.GetType().GetMethod('DownloadString').Invoke($wc, @('http://example.com'))"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "$wc.DownloadString('http://example.com')")

    def test_dynamic_method_call_literal(self):
        code = "'hello'.('Substring')(1, 3)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'ell'")

    def test_dynamic_method_call_concatenated(self):
        code = "'hello'.('Sub' + 'string')(0, 2)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'he'")

    def test_dynamic_member_access_literal(self):
        code = "'hello'.('Length')"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "5")

    def test_dynamic_static_member_access(self):
        code = "[System.Math]::('Max')(10, 20)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "20")

    def test_reflection_property_getvalue_static(self):
        code = "[System.AppDomain].GetProperty('CurrentDomain').GetValue($null, $null)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "[System.AppDomain]::CurrentDomain")

    def test_reflection_field_getvalue_static(self):
        code = "[System.Type].GetField('EmptyTypes').GetValue($null)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "[System.Type]::EmptyTypes")

    def test_reflection_variable_tracking(self):
        code = (
            "$m = [System.IO.File].GetMethod('WriteAllText')\n"
            "$m.Invoke($null, @('test.txt', 'payload'))"
        )
        result = self._parse_and_unwrap(code)
        lines = result.split("\n")
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], "[System.IO.File]::WriteAllText('test.txt', 'payload')")

    def test_type_gettype_reduction(self):
        code = "[System.Type]::GetType('System.Convert')"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "[System.Convert]")

    def test_chained_gettype_getmethod_invoke(self):
        code = "[System.Type]::GetType('System.IO.File').GetMethod('ReadAllText').Invoke($null, @('foo.txt'))"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "[System.IO.File]::ReadAllText('foo.txt')")

    def test_string_instance_methods(self):
        # Substring
        self.assertEqual(self._parse_and_unwrap("'Hello World'.Substring(6)"), "'World'")
        self.assertEqual(self._parse_and_unwrap("'Hello World'.Substring(0, 5)"), "'Hello'")
        # Case conversions
        self.assertEqual(self._parse_and_unwrap("'Hello'.ToLower()"), "'hello'")
        self.assertEqual(self._parse_and_unwrap("'Hello'.ToUpper()"), "'HELLO'")
        # Trimming
        self.assertEqual(self._parse_and_unwrap("'  test  '.Trim()"), "'test'")
        self.assertEqual(self._parse_and_unwrap("'  test  '.TrimStart()"), "'test  '")
        self.assertEqual(self._parse_and_unwrap("'  test  '.TrimEnd()"), "'  test'")
        # Replace
        self.assertEqual(self._parse_and_unwrap("'Hello World'.Replace('World', 'PS')"), "'Hello PS'")
        # Contains, StartsWith, EndsWith
        self.assertEqual(self._parse_and_unwrap("'Hello World'.Contains('world')"), "$true")
        self.assertEqual(self._parse_and_unwrap("'Hello World'.StartsWith('he')"), "$true")
        self.assertEqual(self._parse_and_unwrap("'Hello World'.EndsWith('ld')"), "$true")
        # IndexOf
        self.assertEqual(self._parse_and_unwrap("'Hello'.IndexOf('e')"), "1")
        # Padding
        self.assertEqual(self._parse_and_unwrap("'42'.PadLeft(5, '0')"), "'00042'")
        self.assertEqual(self._parse_and_unwrap("'42'.PadRight(5, '0')"), "'42000'")
        # Insert & Remove
        self.assertEqual(self._parse_and_unwrap("'123'.Insert(1, 'X')"), "'1X23'")
        self.assertEqual(self._parse_and_unwrap("'12345'.Remove(2, 2)"), "'125'")

    def test_static_string_and_math_methods(self):
        # [System.String]::Concat
        self.assertEqual(self._parse_and_unwrap("[System.String]::Concat('foo', 'bar', 'baz')"), "'foobarbaz'")
        # [System.String]::Join
        self.assertEqual(self._parse_and_unwrap("[System.String]::Join('-', @('a', 'b', 'c'))"), "'a-b-c'")
        # [System.String]::IsNullOrEmpty
        self.assertEqual(self._parse_and_unwrap("[System.String]::IsNullOrEmpty('')"), "$true")
        self.assertEqual(self._parse_and_unwrap("[System.String]::IsNullOrEmpty('abc')"), "$false")
        # [System.String]::IsNullOrWhiteSpace
        self.assertEqual(self._parse_and_unwrap("[System.String]::IsNullOrWhiteSpace('   ')"), "$true")
        # [System.Math]
        self.assertEqual(self._parse_and_unwrap("[System.Math]::Abs(-99)"), "99")
        self.assertEqual(self._parse_and_unwrap("[System.Math]::Max(10, 25)"), "25")
        self.assertEqual(self._parse_and_unwrap("[System.Math]::Min(10, 25)"), "10")

    def test_scriptblock_invoke(self):
        code = "{ Write-Host 'Executed' }.Invoke()"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "Write-Host 'Executed'")

    def test_argument_unpacking_typecast(self):
        code = "[System.IO.File].GetMethod('WriteAllText').Invoke($null, [object[]]@('a.txt', 'data'))"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "[System.IO.File]::WriteAllText('a.txt', 'data')")

    def test_argument_unpacking_parentheses(self):
        code = "[System.IO.File].GetMethod('ReadAllText').Invoke($null, ('a.txt'))"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "[System.IO.File]::ReadAllText('a.txt')")

    def test_amsi_bypass_reflection_pattern(self):
        code = "([type]'System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, $true)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "[System.Management.Automation.AmsiUtils]::amsiInitFailed = $true")

    def test_end_to_end_deobfuscator_convergence(self):
        # Combines backtick evasion, string concatenation, and reflection unwrapping
        code = (
            "$path = 'C:\\temp\\' + 'test.txt'\n"
            "[System.IO.File].Get`M`ethod('Read' + 'AllText').Invoke($null, @($path))"
        )
        deobfuscated = self.deobfuscator.deobfuscate(code)
        self.assertIn("[System.IO.File]::ReadAllText", deobfuscated)
        self.assertIn("'C:\\temp\\test.txt'", deobfuscated)

    def test_safety_bounds_handling(self):
        # Out of bounds substring should safely degrade without crashing
        code = "'short'.Substring(100)"
        result = self._parse_and_unwrap(code)
        self.assertEqual(result, "'short'.Substring(100)")


if __name__ == "__main__":
    unittest.main()
