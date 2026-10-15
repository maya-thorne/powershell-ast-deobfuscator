"""
Unit and integration tests for PowerShell Base64 Encoded Command Recursive Unwrapper engine.
Tests parameter aliases, flags, multi-encoding detection, padding repairs,
nested multi-layer unwrapping, AST transformations, and loop guards.
"""

import base64
import unittest

from src.ast_nodes import CommandNode, IdentifierNode, ScriptBlockNode, StringLiteralNode
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.encoded_command_unwrapper import (
    EncodedCommandLayer,
    PowerShellEncodedCommandUnwrapper,
    UnwrapResult,
    calculate_entropy,
    decode_b64_payload,
    is_encoded_command_flag,
)
from src.parser import PowerShellParser
from src.lexer import PowerShellLexer


def encode_utf16le_b64(text: str) -> str:
    """Helper creating standard PowerShell UTF-16LE Base64 strings."""
    return base64.b64encode(text.encode("utf-16le")).decode("ascii")


def encode_utf8_b64(text: str) -> str:
    """Helper creating UTF-8 Base64 strings."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class TestEncodedCommandFlagAndEntropy(unittest.TestCase):
    """Tests flag parsing, prefix aliases, backticks, and Shannon entropy metrics."""

    def test_valid_flag_aliases(self):
        valid = [
            "-e", "-en", "-enc", "-enco", "-encod", "-encode", "-encoded",
            "-encodedc", "-encodedco", "-encodedcom", "-encodedcomm",
            "-encodedcomma", "-encodedcomman", "-encodedcommand",
            "/e", "/enc", "/encodedcommand",
            "-E", "-ENC", "-EncodedCommand",
            "-e`nc", "-`enc", "-E`n`c`o`d`e`d`C`o`m`m`a`n`d",
            "-enc:payload", "-enc=payload", "/e:payload",
        ]
        for flag in valid:
            self.assertTrue(is_encoded_command_flag(flag), f"Expected True for {flag}")

    def test_invalid_flags(self):
        invalid = [
            "-ExecutionPolicy", "-ep", "-exec",
            "-NoProfile", "-nop",
            "-WindowStyle", "-w",
            "-Command", "-c",
            "-File", "-f",
            "powershell", "encodedcommand", "", None,
        ]
        for flag in invalid:
            self.assertFalse(is_encoded_command_flag(flag), f"Expected False for {flag}")

    def test_entropy_calculation(self):
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_entropy(b""), 0.0)

        # Uniform repetition has low entropy
        low_ent = calculate_entropy("AAAAAAAAAA")
        self.assertEqual(low_ent, 0.0)

        # Natural language has moderate entropy (~3.0 - 4.5)
        text_ent = calculate_entropy("Write-Host 'Hello World'")
        self.assertGreater(text_ent, 2.5)
        self.assertLess(text_ent, 5.0)

        # Base64 encoded payload has higher entropy (~5.0 - 6.5)
        b64 = encode_utf16le_b64("Write-Host 'Super Secret Internal Payload Command'")
        b64_ent = calculate_entropy(b64)
        self.assertGreater(b64_ent, text_ent)


class TestDecodeB64Payload(unittest.TestCase):
    """Tests Base64 payload decoding, padding repairs, BOM, and multi-encoding detection."""

    def test_utf16le_decoding(self):
        script = "Write-Host 'Deobfuscated Successfully'"
        b64 = encode_utf16le_b64(script)
        decoded, enc = decode_b64_payload(b64)
        self.assertEqual(decoded, script)
        self.assertEqual(enc, "utf-16le")

    def test_utf8_decoding(self):
        script = "Get-Process | Stop-Process"
        b64 = encode_utf8_b64(script)
        decoded, enc = decode_b64_payload(b64)
        self.assertEqual(decoded, script)
        self.assertEqual(enc, "utf-8")

    def test_utf16le_bom_decoding(self):
        raw_bytes = b"\xff\xfe" + "Write-Output 12345".encode("utf-16le")
        b64 = base64.b64encode(raw_bytes).decode("ascii")
        decoded, enc = decode_b64_payload(b64)
        self.assertEqual(decoded, "Write-Output 12345")
        self.assertEqual(enc, "utf-16le")

    def test_utf8_bom_decoding(self):
        raw_bytes = b"\xef\xbb\xbf" + "Invoke-Expression 'test'".encode("utf-8")
        b64 = base64.b64encode(raw_bytes).decode("ascii")
        decoded, enc = decode_b64_payload(b64)
        self.assertEqual(decoded, "Invoke-Expression 'test'")
        self.assertEqual(enc, "utf-8")

    def test_padding_auto_repair(self):
        script = "Write-Host 'Padding Test'"
        b64 = encode_utf16le_b64(script)
        # Strip trailing padding '=' or '=='
        unpadded = b64.rstrip("=")
        decoded, enc = decode_b64_payload(unpadded)
        self.assertEqual(decoded, script)
        self.assertEqual(enc, "utf-16le")

    def test_whitespace_and_newlines_stripping(self):
        script = "Get-Service wuauserv"
        b64 = encode_utf16le_b64(script)
        # Inject arbitrary whitespaces, tabs, newlines inside Base64 string
        dirty_b64 = f"{b64[:10]}\r\n  {b64[10:20]}\t  {b64[20:]}"
        decoded, enc = decode_b64_payload(dirty_b64)
        self.assertEqual(decoded, script)
        self.assertEqual(enc, "utf-16le")

    def test_backticks_in_payload(self):
        script = "Write-Host 'Backtick payload test'"
        b64 = encode_utf16le_b64(script)
        # Inject evasion backticks into Base64 string: V`w`B`y...
        backticked_b64 = "`".join(b64[:12]) + b64[12:]
        decoded, enc = decode_b64_payload(backticked_b64)
        self.assertEqual(decoded, script)
        self.assertEqual(enc, "utf-16le")

    def test_url_safe_base64(self):
        # Create a payload that contains + and / then convert to urlsafe - and _
        payload = b"test+data/123" * 5
        raw_b64 = base64.b64encode(payload).decode("ascii")
        url_safe = raw_b64.replace("+", "-").replace("/", "_")
        decoded, enc = decode_b64_payload(url_safe)
        self.assertIsNotNone(decoded)

    def test_malformed_payload(self):
        self.assertEqual(decode_b64_payload(""), (None, None))
        self.assertEqual(decode_b64_payload("abc"), (None, None))
        self.assertEqual(decode_b64_payload("!@#$%^&*()"), (None, None))


class TestTextLevelUnwrapping(unittest.TestCase):
    """Tests text-level regex scanning, CLI launchers, flags extraction, and nested loops."""

    def setUp(self):
        self.unwrapper = PowerShellEncodedCommandUnwrapper()

    def test_standard_powershell_enc(self):
        script = "Write-Host 'Standard Execution'"
        b64 = encode_utf16le_b64(script)
        raw_cmd = f"powershell.exe -enc {b64}"
        res = self.unwrapper.unwrap_text(raw_cmd)
        self.assertTrue(res.has_encoded_commands)
        self.assertEqual(res.total_layers, 1)
        self.assertEqual(res.unwrapped_script, script)
        self.assertEqual(res.layers[0].cli_binary, "powershell.exe")

    def test_cli_variations(self):
        script = "whoami /all"
        b64 = encode_utf16le_b64(script)

        variants = [
            f"powershell -e {b64}",
            f"pwsh -enc {b64}",
            f"pwsh.exe -EncodedCommand {b64}",
            f"& 'powershell.exe' -enc {b64}",
            f"cmd.exe /c powershell -enc {b64}",
            f"/enc {b64}",
        ]
        for cmd in variants:
            res = self.unwrapper.unwrap_text(cmd)
            self.assertTrue(res.has_encoded_commands, f"Failed for {cmd}")
            self.assertEqual(res.unwrapped_script, script)

    def test_cli_with_obfuscated_flags(self):
        script = "Invoke-Item 'C:\\temp\\file.txt'"
        b64 = encode_utf16le_b64(script)
        cmd = f"powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -enc {b64}"
        res = self.unwrapper.unwrap_text(cmd)
        self.assertEqual(res.unwrapped_script, script)
        self.assertEqual(res.total_layers, 1)
        layer = res.layers[0]
        self.assertIn("-NoProfile", layer.flags)
        self.assertIn("-ExecutionPolicy", layer.flags)

    def test_quoted_and_parenthesized_concatenation(self):
        script = "Write-Host 'Concatenated payload'"
        b64 = encode_utf16le_b64(script)
        mid = len(b64) // 2
        part1 = b64[:mid]
        part2 = b64[mid:]

        # Parenthesized string concatenation in command line: powershell -enc ('part1' + 'part2')
        cmd = f"powershell.exe -enc ('{part1}' + '{part2}')"
        res = self.unwrapper.unwrap_text(cmd)
        self.assertEqual(res.unwrapped_script, script)

    def test_recursive_nested_2_layers(self):
        # Layer 2 (innermost): Write-Host 'Inner Core'
        inner_script = "Write-Host 'Inner Core'"
        b64_inner = encode_utf16le_b64(inner_script)
        # Layer 1: powershell.exe -w hidden -enc <b64_inner>
        mid_cmd = f"powershell.exe -w hidden -enc {b64_inner}"
        b64_outer = encode_utf16le_b64(mid_cmd)
        # Outer CLI invocation
        outer_cmd = f"powershell.exe -NoProfile -enc {b64_outer}"

        res = self.unwrapper.unwrap_text(outer_cmd)
        self.assertTrue(res.has_encoded_commands)
        self.assertEqual(res.total_layers, 2)
        self.assertEqual(res.unwrapped_script, inner_script)
        self.assertEqual(res.layers[0].depth, 1)
        self.assertEqual(res.layers[1].depth, 2)

    def test_recursive_nested_3_layers(self):
        l3 = "Get-ComputerInfo | Out-File sysinfo.txt"
        b64_3 = encode_utf16le_b64(l3)
        l2 = f"pwsh.exe -e {b64_3}"
        b64_2 = encode_utf16le_b64(l2)
        l1 = f"powershell.exe -ep bypass -enc {b64_2}"
        b64_1 = encode_utf16le_b64(l1)
        outer = f"cmd.exe /c powershell -enc {b64_1}"

        res = self.unwrapper.unwrap_text(outer)
        self.assertEqual(res.total_layers, 3)
        self.assertEqual(res.unwrapped_script, l3)

    def test_cyclic_loop_guard(self):
        # Construct payload that decodes to itself
        fake_b64 = encode_utf16le_b64("powershell -enc AAAA")
        # Should terminate cleanly without hanging or infinite loop
        res = self.unwrapper.unwrap_text(f"powershell -enc {fake_b64}", max_depth=10)
        self.assertIsNotNone(res.unwrapped_script)

    def test_max_depth_limit(self):
        l2 = "Write-Host 'Done'"
        b64_2 = encode_utf16le_b64(l2)
        l1 = f"powershell -enc {b64_2}"
        b64_1 = encode_utf16le_b64(l1)
        outer = f"powershell -enc {b64_1}"

        # If max_depth is 1, only 1 layer should be unwrapped
        res = self.unwrapper.unwrap_text(outer, max_depth=1)
        self.assertEqual(res.total_layers, 1)
        self.assertIn("powershell -enc", res.unwrapped_script)


class TestASTLevelUnwrapping(unittest.TestCase):
    """Tests AST visitor transformations on CommandNode and nested pipelines."""

    def setUp(self):
        self.unwrapper = PowerShellEncodedCommandUnwrapper(inline_ast=True)

    def test_command_node_inlining(self):
        inner_script = "Write-Host 'AST Unwrapped'"
        b64 = encode_utf16le_b64(inner_script)

        # Build AST: powershell.exe -enc <b64>
        cmd_node = CommandNode(
            target=IdentifierNode("powershell.exe"),
            arguments=[IdentifierNode("-enc"), StringLiteralNode(b64)],
        )

        unwrapped_ast = self.unwrapper.unwrap_ast(cmd_node)
        # Should be inlined as CommandNode(target=IdentifierNode("Write-Host"), arguments=[StringLiteralNode("AST Unwrapped")])
        self.assertIsInstance(unwrapped_ast, CommandNode)
        self.assertEqual(unwrapped_ast.target.name, "Write-Host")
        self.assertEqual(len(unwrapped_ast.arguments), 1)
        self.assertEqual(unwrapped_ast.arguments[0].value, "AST Unwrapped")

    def test_scriptblock_containing_encoded_command(self):
        inner_script = "Get-Process -Name lsass"
        b64 = encode_utf16le_b64(inner_script)

        ps_code = f"& {{ powershell -enc {b64} }}"
        lexer = PowerShellLexer(ps_code)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()

        unwrapped_ast = self.unwrapper.unwrap_ast(ast)
        self.assertIsInstance(unwrapped_ast, ScriptBlockNode)
        first_stmt = unwrapped_ast.statements[0]
        # Verify CommandNode has target Get-Process
        if isinstance(first_stmt, CommandNode):
            self.assertEqual(first_stmt.target.name, "Get-Process")


class TestEndToEndDeobfuscationIntegration(unittest.TestCase):
    """Tests full integration with PowerShellDeobfuscator and cascading passes."""

    def setUp(self):
        self.engine = PowerShellDeobfuscator()

    def test_full_deobfuscator_with_nested_ast_obfuscation(self):
        # Inner payload contains backtick evasion and format operator:
        # In`voke-Exp`ression ('{0}{1}' -f 'Get-', 'Process')
        inner_payload = "In`voke-Exp`ression ('{0}{1}' -f 'Get-', 'Process')"
        b64 = encode_utf16le_b64(inner_payload)

        # Wrap in powershell -NoProfile -enc
        obfuscated_cmd = f"powershell.exe -NoProfile -enc {b64}"

        engine = PowerShellDeobfuscator(unwrap_iex=False)
        result = engine.deobfuscate(obfuscated_cmd)
        # Verify that Base64 unwrapping + backtick stripping + format folding all happened!
        self.assertIn("Invoke-Expression", result)
        self.assertIn("Get-Process", result)
        self.assertNotIn("`", result)
        self.assertNotIn("-f", result)

    def test_full_deobfuscator_multi_layer_nesting(self):
        l2 = "Write-Host ('Co' + 're')"
        b64_2 = encode_utf16le_b64(l2)
        l1 = f"powershell -w hidden -enc {b64_2}"
        b64_1 = encode_utf16le_b64(l1)
        outer = f"powershell.exe -NoP -enc {b64_1}"

        result = self.engine.deobfuscate(outer)
        self.assertIn("Write-Host 'Core'", result)


if __name__ == "__main__":
    unittest.main()
