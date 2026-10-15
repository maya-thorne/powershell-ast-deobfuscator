"""
Unit and integration tests for PowerShell Environment Variable, Automatic Variable,
and ExecutionContext Inlining Engine.
"""

import unittest

from src.ast_nodes import (
    ArrayLiteralNode,
    CommandNode,
    IdentifierNode,
    StringLiteralNode,
    VariableNode,
)
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.environment_inliner import PowerShellEnvironmentInliner
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser


class TestPowerShellEnvironmentInliner(unittest.TestCase):
    """Verifies environment variable resolution, automatic variables, and ExecutionContext methods."""

    def setUp(self):
        self.inliner = PowerShellEnvironmentInliner()

    def _parse(self, code: str):
        tokens = PowerShellLexer(code).tokenize()
        return PowerShellParser(tokens).parse()

    def _normalize(self, code: str) -> str:
        ast = self._parse(code)
        normalizer = PowerShellNormalizer(unwrap_iex=False)
        norm_ast = normalizer.normalize(ast)
        return normalizer.to_source(norm_ast)

    def test_default_env_var_inlining(self):
        code = "$env:COMSPEC"
        res = self._normalize(code)
        self.assertEqual(res, r"'C:\Windows\system32\cmd.exe'")

        code_path = "$env:PATHEXT"
        res_path = self._normalize(code_path)
        self.assertIn(".EXE", res_path)

        code_sys = "$env:SYSTEMROOT"
        res_sys = self._normalize(code_sys)
        self.assertEqual(res_sys, r"'C:\Windows'")

    def test_custom_env_var_inlining(self):
        custom_inliner = PowerShellEnvironmentInliner(env={"PAYLOAD_HOST": "192.168.1.100"})
        var_node = VariableNode(name="PAYLOAD_HOST", scope="env")
        result = custom_inliner.visit_variable(var_node)
        self.assertIsInstance(result, StringLiteralNode)
        self.assertEqual(result.value, "192.168.1.100")

    def test_special_automatic_variables(self):
        pshome_res = self._normalize("$PSHOME")
        self.assertEqual(pshome_res, r"'C:\Windows\System32\WindowsPowerShell\v1.0'")

        shellid_res = self._normalize("$ShellId")
        self.assertEqual(shellid_res, "'Microsoft.PowerShell'")

        verbose_res = self._normalize("$VerbosePreference")
        self.assertEqual(verbose_res, "'SilentlyContinue'")

        confirm_res = self._normalize("$ConfirmPreference")
        self.assertEqual(confirm_res, "'High'")

    def test_environment_indexing_and_join(self):
        code = "$env:COMSPEC[4, 15, 25] -join ''"
        res = self._normalize(code)
        self.assertEqual(res, "'iex'")

        code_slice = "$env:COMSPEC[0..2] -join ''"
        res_slice = self._normalize(code_slice)
        self.assertEqual(res_slice, r"'C:\'")

    def test_shellid_and_preference_indexing(self):
        code_shell = "$ShellId[1, 13, 4] -join ''"
        res_shell = self._normalize(code_shell)
        self.assertEqual(res_shell, "'ieo'")

        code_pref = "$VerbosePreference.ToString()[1, 3] -join ''"
        res_pref = self._normalize(code_pref)
        self.assertEqual(res_pref, "'ie'")

    def test_execution_context_invoke_command_properties(self):
        code = "$ExecutionContext.InvokeCommand"
        res = self._normalize(code)
        self.assertEqual(res, "'System.Management.Automation.CommandInvocationIntrinsics'")

    def test_execution_context_session_state(self):
        code_mode = "$ExecutionContext.SessionState.LanguageMode"
        res_mode = self._normalize(code_mode)
        self.assertEqual(res_mode, "'FullLanguage'")

        code_path = "$ExecutionContext.SessionState.Path"
        res_path = self._normalize(code_path)
        self.assertEqual(res_path, "'System.Management.Automation.PathIntrinsics'")

    def test_execution_context_invoke_script(self):
        code = "$ExecutionContext.InvokeCommand.InvokeScript('Write-Host Success')"
        res = self._normalize(code)
        self.assertEqual(res, "Write-Host Success")

    def test_execution_context_new_script_block(self):
        code = "$ExecutionContext.InvokeCommand.NewScriptBlock('Get-Process -Name lsass')"
        res = self._normalize(code)
        self.assertEqual(res, "Get-Process -Name lsass")

    def test_execution_context_expand_string(self):
        code = "$ExecutionContext.InvokeCommand.ExpandString('$env:COMSPEC')"
        res = self._normalize(code)
        self.assertEqual(res, r"'C:\Windows\system32\cmd.exe'")

    def test_execution_context_get_command(self):
        code = "$ExecutionContext.InvokeCommand.GetCommand('iex')"
        res = self._normalize(code)
        self.assertEqual(res, "'Invoke-Expression'")

    def test_call_operator_reduction_with_environment_slicing(self):
        code = "& ($env:COMSPEC[4, 15, 25] -join '') 'calc.exe'"
        res = self._normalize(code)
        self.assertEqual(res, "iex 'calc.exe'")

    def test_call_operator_reduction_with_symbol_table(self):
        code = "$cmd = $env:COMSPEC[4, 15, 25] -join ''\n& $cmd 'calc.exe'"
        res = self._normalize(code)
        self.assertIn("$cmd = 'iex'", res)
        self.assertIn("iex 'calc.exe'", res)

    def test_expandable_string_variable_interpolation(self):
        code = '"Target: $env:SYSTEMROOT\\system32"'
        res = self._normalize(code)
        self.assertEqual(res, r'"Target: C:\Windows\system32"')

    def test_multi_pass_deobfuscation_end_to_end(self):
        engine = PowerShellDeobfuscator(unwrap_iex=False)
        payload = (
            "$fn = ($env:COMSPEC[4, 15, 25] -join ''); "
            "& $fn ('{1}{0}' -f 'alc.exe', 'c')"
        )
        res = engine.deobfuscate(payload)
        self.assertIn("$fn = 'iex'", res)
        self.assertIn("iex 'calc.exe'", res)


if __name__ == "__main__":
    unittest.main()
