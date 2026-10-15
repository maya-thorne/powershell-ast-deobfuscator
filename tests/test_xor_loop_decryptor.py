"""
Unit and integration tests for PowerShell static XOR loop decryptor.
"""

import unittest

from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser
from src.xor_loop_decryptor import MAX_LOOP_ITERATIONS, PowerShellXorLoopDecryptor


class TestXorLoopDecryptor(unittest.TestCase):
    """Test suite for PowerShellXorLoopDecryptor."""

    def _decrypt(self, code: str, symbols: dict = None) -> str:
        sym = symbols if symbols is not None else {}
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        decryptor = PowerShellXorLoopDecryptor(symbols=sym)
        dec_ast = decryptor.decrypt(ast)
        normalizer = PowerShellNormalizer(symbols=sym)
        return normalizer.to_source(dec_ast).strip()

    def test_pipeline_single_byte_xor_char_cast(self):
        # 105 ('i') ^ 0x20 = 73 ('I')
        # 101 ('e') ^ 0x20 = 69 ('E')
        # 120 ('x') ^ 0x20 = 88 ('X')
        code = "@(73, 69, 88) | % { [char]($_ -bxor 0x20) }"
        res = self._decrypt(code)
        self.assertEqual(res, "'iex'")

    def test_pipeline_single_byte_xor_join(self):
        # 'calc' ^ 0x55
        # 'c': 99 ^ 0x55 = 0x63 ^ 0x55 = 0x36 (54)
        # 'a': 97 ^ 0x55 = 0x61 ^ 0x55 = 0x34 (52)
        # 'l': 108 ^ 0x55 = 0x6c ^ 0x55 = 0x39 (57)
        # 'c': 99 ^ 0x55 = 54
        code = "(@(54, 52, 57, 54) | % { [char]($_ -bxor 0x55) }) -join ''"
        res = self._decrypt(code)
        self.assertEqual(res, "'calc'")

    def test_pipeline_multi_byte_repeating_key(self):
        # Data: 'test' -> [116, 101, 115, 116]
        # Key: [0x10, 0x20]
        # 116 ^ 0x10 = 100
        # 101 ^ 0x20 = 69
        # 115 ^ 0x10 = 99
        # 116 ^ 0x20 = 84
        sym = {"k": [0x10, 0x20]}
        code = "(@(100, 69, 99, 84) | % { [char]($_ -bxor $k[$i++ % $k.Length]) }) -join ''"
        res = self._decrypt(code, sym)
        self.assertEqual(res, "'test'")

    def test_pipeline_string_key_xor(self):
        # Key: 'A' (65)
        # 'p' (112) ^ 65 = 49
        # 's' (115) ^ 65 = 50
        sym = {"key": "A"}
        code = "@(49, 50) | % { [char]($_ -bxor $key) }"
        res = self._decrypt(code, sym)
        self.assertEqual(res, "'ps'")

    def test_static_encoding_wrapper(self):
        # [System.Text.Encoding]::ASCII.GetString(@(105, 101, 120) | % { $_ -bxor 0 }) -> 'iex'
        code = "[System.Text.Encoding]::ASCII.GetString(@(105, 101, 120) | % { $_ -bxor 0 })"
        res = self._decrypt(code)
        self.assertEqual(res, "'iex'")

    def test_static_utf8_encoding_wrapper(self):
        code = "[System.Text.Encoding]::UTF8.GetString(@(105, 101, 120) | % { $_ -bxor 0 })"
        res = self._decrypt(code)
        self.assertEqual(res, "'iex'")

    def test_imperative_for_loop_string_accumulator(self):
        # for ($i = 0; $i -lt $enc.Length; $i++) { $out += [char]($enc[$i] -bxor 0x33) }
        # 'cmd':
        # 'c': 99 ^ 0x33 = 0x63 ^ 0x33 = 0x50 (80)
        # 'm': 109 ^ 0x33 = 0x6d ^ 0x33 = 0x5e (94)
        # 'd': 100 ^ 0x33 = 0x64 ^ 0x33 = 0x57 (87)
        sym = {"enc": [80, 94, 87]}
        code = "for ($i = 0; $i -lt $enc.Length; $i++) { $out += [char]($enc[$i] -bxor 0x33) }"
        res = self._decrypt(code, sym)
        self.assertIn("$out = 'cmd'", res)
        self.assertEqual(sym.get("out"), "cmd")

    def test_imperative_for_loop_inplace_mutation(self):
        # for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor 0x10 }
        sym = {"b": [116 ^ 0x10, 101 ^ 0x10]}
        code = "for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor 0x10 }"
        res = self._decrypt(code, sym)
        self.assertEqual(sym["b"], [116, 101])

    def test_imperative_foreach_loop(self):
        # foreach ($b in $enc) { $out += [char]($b -bxor 0x22) }
        # 'ps': 112 ^ 0x22 = 82, 115 ^ 0x22 = 81
        sym = {"enc": [82, 81]}
        code = "foreach ($b in $enc) { $out += [char]($b -bxor 0x22) }"
        res = self._decrypt(code, sym)
        self.assertIn("$out = 'ps'", res)
        self.assertEqual(sym.get("out"), "ps")

    def test_imperative_while_loop(self):
        # while ($i -lt $enc.Length) { $out += [char]($enc[$i] -bxor 0x55); $i++ }
        sym = {"enc": [54, 52, 57, 54]}  # 'calc'
        code = "while ($i -lt $enc.Length) { $out += [char]($enc[$i] -bxor 0x55); $i++ }"
        res = self._decrypt(code, sym)
        self.assertIn("$out = 'calc'", res)
        self.assertEqual(sym.get("out"), "calc")

    def test_base64_source_xor(self):
        # [Convert]::FromBase64String('...') | % { [char]($_ -bxor 0x11) }
        # 'ok': 111 ^ 0x11 = 126 ('~'), 107 ^ 0x11 = 122 ('z')
        # bytes [126, 122] in base64: fno=
        code = "[System.Convert]::FromBase64String('fno=') | % { [char]($_ -bxor 0x11) }"
        res = self._decrypt(code)
        self.assertEqual(res, "'ok'")

    def test_loop_iteration_guard(self):
        # Loops exceeding MAX_LOOP_ITERATIONS should be rejected safely
        sym = {"huge": list(range(MAX_LOOP_ITERATIONS + 10))}
        code = "for ($i = 0; $i -lt $huge.Length; $i++) { $out += [char]($huge[$i] -bxor 0x55) }"
        res = self._decrypt(code, sym)
        # Should retain for loop and not resolve to a constant string assignment
        self.assertTrue(res.startswith("for ("))
        self.assertNotIn("sym", sym.get("out", ""))

    def test_deobfuscator_end_to_end_xor_cradle(self):
        # Emulates classic malware cradle:
        # $bytes = @(80, 83); $cmd = ($bytes | % { [char]($_ -bxor 0) }) -join ''; iex $cmd
        script = "$bytes = @(105, 101, 120); $cmd = ($bytes | % { [char]($_ -bxor 0x00) }) -join ''; & $cmd 'calc.exe'"
        engine = PowerShellDeobfuscator(unwrap_iex=False)
        deobf = engine.deobfuscate(script)
        self.assertIn("iex 'calc.exe'", deobf)


if __name__ == "__main__":
    unittest.main()
