"""
Unit tests for SecureString cryptographic engine, static key extractor,
and AST reduction pipeline.
"""

import unittest
from src.ast_nodes import (
    ArrayLiteralNode,
    CommandNode,
    IdentifierNode,
    NumberLiteralNode,
    ParenthesizedExpressionNode,
    RangeExpressionNode,
    StaticMemberAccessNode,
    StringLiteralNode,
    TypeCastNode,
    VariableNode,
)
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser
from src.secure_string_crypto import (
    InvalidKeyLengthError,
    InvalidSecureStringFormatError,
    SecureStringDecryptionError,
    SecureStringError,
    decrypt_secure_string,
    encrypt_secure_string,
    zeroize_buffer,
)
from src.secure_string_reducer import PowerShellSecureStringReducer
from src.static_key_extractor import StaticKeyExtractor


class TestSecureStringCrypto(unittest.TestCase):
    def setUp(self):
        self.key16 = bytes(range(1, 17))
        self.key24 = bytes(range(1, 25))
        self.key32 = bytes(range(1, 33))

    def test_zeroize_buffer_memory_scrubbing(self):
        """Verifies zeroize_buffer resets bytearray and list contents to zeroes."""
        buf_ba = bytearray(b"SecretKeyMaterial123")
        zeroize_buffer(buf_ba)
        self.assertTrue(all(b == 0 for b in buf_ba))

        buf_list = [1, 2, 3, 4, 5]
        zeroize_buffer(buf_list)
        self.assertEqual(buf_list, [0, 0, 0, 0, 0])

    def test_authentic_powershell_v2_sample_decryption(self):
        """Decrypts authentic Windows PowerShell ConvertFrom-SecureString payload."""
        raw_v2_sample = (
            "76492d1116743f0423413b16050a5345"
            "MgB8AHkANwBEADMAMQBIAHEAZQBhAHcAOABOAFMAZgBvAHMATgBwAFkATABRAHcAPQA9AHw"
            "AZAA2ADgAMgBkADUANwA1AGIAMwBmADYANwA5ADgANAAyADgANgAwAGEAYQBhAGYANwAyAG"
            "YANABhAGEAYQA1ADMAOQBhAGIAMQBlAGQAMQAyADAAMAA4ADgAZAAzADkAYgBiADAAYwAzA"
            "GEAMgA1AGYAZgA1ADEAMgA2AGUAOQA="
        )
        decrypted = decrypt_secure_string(raw_v2_sample, self.key16)
        self.assertEqual(decrypted, "Secret123")

        # Test pure-Python engine fallback on identical payload
        decrypted_py = decrypt_secure_string(raw_v2_sample, self.key16, use_pure_python=True)
        self.assertEqual(decrypted_py, "Secret123")

    def test_round_trip_encryption_and_decryption(self):
        """Verifies round-trip encryption and decryption across 128, 192, and 256-bit keys."""
        payload = "Invoke-Expression 'Get-Process -Name powershell'"
        for key in (self.key16, self.key24, self.key32):
            enc = encrypt_secure_string(payload, key)
            self.assertTrue(enc.startswith("76492d1116743f0423413b16050a5345"))

            dec = decrypt_secure_string(enc, key)
            self.assertEqual(dec, payload)

            dec_py = decrypt_secure_string(enc, key, use_pure_python=True)
            self.assertEqual(dec_py, payload)

    def test_error_handling_malformed_secure_string(self):
        """Verifies custom exceptions for invalid formats and keys."""
        # Missing GUID header
        with self.assertRaises(InvalidSecureStringFormatError):
            decrypt_secure_string("NotAValidSecureStringFormat", self.key16)

        # Invalid key size (e.g. 10 bytes)
        valid_enc = encrypt_secure_string("test", self.key16)
        with self.assertRaises(InvalidKeyLengthError):
            decrypt_secure_string(valid_enc, b"shortkey")

        # Corrupted payload base64
        with self.assertRaises(InvalidSecureStringFormatError):
            decrypt_secure_string("76492d1116743f0423413b16050a5345!!!corrupt", self.key16)

        # Corrupted ciphertext / wrong key leading to decryption/padding error
        with self.assertRaises(SecureStringDecryptionError):
            decrypt_secure_string(valid_enc, bytes([0xFF] * 16))


class TestStaticKeyExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = StaticKeyExtractor()
        self.key16 = bytes(range(1, 17))
        self.key32 = bytes(range(1, 33))

    def test_extract_key_from_range_node(self):
        """Tests key recovery from range expressions: 1..16 and 1..32."""
        range_node = RangeExpressionNode(
            start=NumberLiteralNode(value=1, raw="1"),
            end=NumberLiteralNode(value=16, raw="16"),
        )
        key = self.extractor.extract_key(range_node)
        self.assertEqual(key, self.key16)

        range32 = RangeExpressionNode(
            start=NumberLiteralNode(value=1, raw="1"),
            end=NumberLiteralNode(value=32, raw="32"),
        )
        self.assertEqual(self.extractor.extract_key(range32), self.key32)

    def test_extract_key_from_array_literal(self):
        """Tests key recovery from @(1, 2, ..., 16)."""
        elements = [NumberLiteralNode(value=i, raw=str(i)) for i in range(1, 17)]
        array_node = ArrayLiteralNode(elements=elements)
        key = self.extractor.extract_key(array_node)
        self.assertEqual(key, self.key16)

    def test_extract_key_from_type_cast(self):
        """Tests key recovery from [byte[]](1..16)."""
        range_node = RangeExpressionNode(
            start=NumberLiteralNode(value=1, raw="1"),
            end=NumberLiteralNode(value=16, raw="16"),
        )
        cast_node = TypeCastNode(
            type_name="byte[]",
            expression=ParenthesizedExpressionNode(expression=range_node),
        )
        key = self.extractor.extract_key(cast_node)
        self.assertEqual(key, self.key16)

    def test_extract_key_from_variable_table(self):
        """Tests key recovery through tracked variable symbols."""
        symbols = {"my_aes_key": self.key16}
        extractor = StaticKeyExtractor(symbols=symbols)
        var_node = VariableNode(name="my_aes_key")
        self.assertEqual(extractor.extract_key(var_node), self.key16)

    def test_extract_key_from_utf8_encoding(self):
        """Tests key recovery from [System.Text.Encoding]::UTF8.GetBytes('SixteenBytesKey!')."""
        node = StaticMemberAccessNode(
            type_name="System.Text.Encoding",
            member="GetBytes",
            arguments=[StringLiteralNode(value="SixteenBytesKey!")],
        )
        key = self.extractor.extract_key(node)
        self.assertEqual(key, b"SixteenBytesKey!")


class TestSecureStringReducer(unittest.TestCase):
    def setUp(self):
        self.key16 = bytes(range(1, 17))
        self.reducer = PowerShellSecureStringReducer()

    def test_reduce_convert_to_secure_string_plain_text(self):
        """Tests reduction of ConvertTo-SecureString 'Payload' -AsPlainText -Force."""
        code = "ConvertTo-SecureString 'CleanPayload' -AsPlainText -Force"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        reduced = self.reducer.reduce(ast)
        stmt = reduced.statements[0]
        self.assertIsInstance(stmt, StringLiteralNode)
        self.assertEqual(stmt.value, "CleanPayload")

    def test_reduce_convert_to_secure_string_piped_plain_text(self):
        """Tests reduction of 'Payload' | ConvertTo-SecureString -AsPlainText -Force."""
        code = "'PipedPayload' | ConvertTo-SecureString -AsPlainText -Force"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        reduced = self.reducer.reduce(ast)
        stmt = reduced.statements[0]
        self.assertIsInstance(stmt, StringLiteralNode)
        self.assertEqual(stmt.value, "PipedPayload")

    def test_reduce_marshal_unboxing(self):
        """Tests reduction of [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(...)."""
        code = (
            "[System.Runtime.InteropServices.Marshal]::PtrToStringAuto("
            "[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR("
            "(ConvertTo-SecureString 'UnboxedSecret' -AsPlainText -Force)))"
        )
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        normalizer = PowerShellNormalizer()
        norm_ast = normalizer.normalize(ast)
        src = normalizer.to_source(norm_ast)
        self.assertEqual(src, "'UnboxedSecret'")

    def test_reduce_network_credential_unboxing(self):
        """Tests reduction of [System.Net.NetworkCredential]::new('', $sec).Password."""
        code = (
            "[System.Net.NetworkCredential]::new('', "
            "(ConvertTo-SecureString 'NetCredSecret' -AsPlainText -Force)).Password"
        )
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        normalizer = PowerShellNormalizer()
        norm_ast = normalizer.normalize(ast)
        src = normalizer.to_source(norm_ast)
        self.assertEqual(src, "'NetCredSecret'")

    def test_reduce_new_object_credential_unboxing(self):
        """Tests reduction of (New-Object System.Management.Automation.PSCredential('user', $sec)).GetNetworkCredential().Password."""
        code = (
            "(New-Object System.Management.Automation.PSCredential('admin', "
            "(ConvertTo-SecureString 'PSCredSecret' -AsPlainText -Force))).GetNetworkCredential().Password"
        )
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        normalizer = PowerShellNormalizer()
        norm_ast = normalizer.normalize(ast)
        src = normalizer.to_source(norm_ast)
        self.assertEqual(src, "'PSCredSecret'")

    def test_multi_pass_deobfuscation_with_encrypted_string(self):
        """Tests full end-to-end multi-pass convergence on encrypted SecureString payload."""
        secret_payload = "Write-Host 'Decrypted Payload 100% OK'"
        enc_str = encrypt_secure_string(secret_payload, self.key16)

        script = (
            f"$enc = '{enc_str}'\n"
            f"$key = 1..16\n"
            f"$sec = ConvertTo-SecureString $enc -Key $key\n"
            f"$cmd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))\n"
            f"Invoke-Expression $cmd"
        )

        engine = PowerShellDeobfuscator()
        result = engine.deobfuscate(script)
        self.assertIn("Decrypted Payload 100% OK", result)


if __name__ == "__main__":
    unittest.main()
