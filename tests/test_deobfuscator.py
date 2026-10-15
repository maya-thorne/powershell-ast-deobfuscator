"""Unit tests for multi-pass fixed-point PowerShell deobfuscator engine."""

import unittest
from src.deobfuscator_engine import PowerShellDeobfuscator


class TestPowerShellDeobfuscator(unittest.TestCase):
    def setUp(self):
        self.engine = PowerShellDeobfuscator()

    def test_backtick_obfuscation_removal(self):
        code = "In`voke-Exp`ression 'Get-Process'"
        result = PowerShellDeobfuscator(unwrap_iex=False).deobfuscate(code)
        self.assertIn("Invoke-Expression", result)

    def test_nested_format_and_concat(self):
        code = "('{1}{0}' -f ('l'+'d'), ('Wor'+''))"
        result = self.engine.deobfuscate(code)
        self.assertIn("'World'", result)

    def test_base64_encoded_command_unwrapping(self):
        # 'Write-Host Success' in UTF-16LE base64:
        # VwByAGkAdABlAC0ASABvAHMAdAAgAFMAdQBjAGMAZQBzAHMA
        b64_payload = "VwByAGkAdABlAC0ASABvAHMAdAAgAFMAdQBjAGMAZQBzAHMA"
        code = f"powershell.exe -enc {b64_payload}"
        result = self.engine.deobfuscate(code)
        self.assertIn("Write-Host Success", result)


if __name__ == "__main__":
    unittest.main()
