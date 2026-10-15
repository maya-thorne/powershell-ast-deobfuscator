"""
Unit and integration tests for AMSI & ETW bypass signature detection and ruleset engine.
Verifies memory patching detection, reflection tampering detection, neutralization modes,
CLI integration, and deobfuscator engine integration.
"""

import io
import json
import unittest
from unittest.mock import patch

from src.amsi_etw_detector import (
    PowerShellAmsiEtwDetector,
    SanitizationResult,
    detect_amsi_etw,
    neutralize_amsi_etw,
)
from src.amsi_etw_signatures import (
    BUILTIN_SIGNATURES,
    DEFAULT_RULESET,
    AmsiEtwFinding,
    AmsiEtwRuleSet,
    BypassCategory,
    BypassSeverity,
    BypassSignature,
    TargetSystem,
)
from src.cli import main
from src.deobfuscator_engine import PowerShellDeobfuscator


class TestAmsiEtwSignaturesAndRuleSet(unittest.TestCase):
    """Verifies signature catalog, ruleset queries, filtering, and serialization."""

    def setUp(self):
        self.ruleset = DEFAULT_RULESET

    def test_builtin_signatures_loaded(self):
        self.assertGreaterEqual(len(self.ruleset), 10)
        sig_ids = [s.id for s in self.ruleset.all_signatures()]
        self.assertIn("AMSI-MEM-001", sig_ids)
        self.assertIn("ETW-MEM-001", sig_ids)
        self.assertIn("AMSI-REFL-001", sig_ids)
        self.assertIn("ETW-REFL-001", sig_ids)
        self.assertIn("ETW-REFL-002", sig_ids)
        self.assertIn("LOG-REFL-001", sig_ids)

    def test_filter_by_target_system(self):
        amsi_rules = self.ruleset.by_target(TargetSystem.AMSI)
        self.assertTrue(all(r.target_system == TargetSystem.AMSI for r in amsi_rules))
        self.assertGreaterEqual(len(amsi_rules), 3)

        etw_rules = self.ruleset.by_target(TargetSystem.ETW)
        self.assertTrue(all(r.target_system == TargetSystem.ETW for r in etw_rules))
        self.assertGreaterEqual(len(etw_rules), 3)

    def test_filter_by_category(self):
        mem_rules = self.ruleset.by_category(BypassCategory.MEMORY_PATCH)
        self.assertTrue(all(r.category == BypassCategory.MEMORY_PATCH for r in mem_rules))
        self.assertGreaterEqual(len(mem_rules), 4)

        refl_rules = self.ruleset.by_category(BypassCategory.REFLECTION_TAMPERING)
        self.assertTrue(all(r.category == BypassCategory.REFLECTION_TAMPERING for r in refl_rules))
        self.assertGreaterEqual(len(refl_rules), 3)

    def test_filter_by_severity(self):
        critical_rules = self.ruleset.by_severity(BypassSeverity.CRITICAL)
        self.assertTrue(all(r.severity == BypassSeverity.CRITICAL for r in critical_rules))
        self.assertGreaterEqual(len(critical_rules), 4)

    def test_signature_serialization(self):
        sig = self.ruleset.get("AMSI-MEM-001")
        self.assertIsNotNone(sig)
        d = sig.to_dict()
        self.assertEqual(d["id"], "AMSI-MEM-001")
        self.assertEqual(d["category"], "memory_patch")
        self.assertEqual(d["target_system"], "amsi")
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["mitre_id"], "T1562.001")

    def test_custom_signature_registration(self):
        custom_ruleset = AmsiEtwRuleSet()
        custom_sig = BypassSignature(
            id="CUSTOM-001",
            name="Custom Bypass Rule",
            category=BypassCategory.MEMORY_PATCH,
            target_system=TargetSystem.AMSI,
            severity=BypassSeverity.HIGH,
            description="Test custom rule",
        )
        custom_ruleset.register(custom_sig)
        self.assertEqual(len(custom_ruleset), 1)
        self.assertEqual(custom_ruleset.get("CUSTOM-001").name, "Custom Bypass Rule")


class TestAmsiMemoryPatchDetection(unittest.TestCase):
    """Verifies memory patch detection against AmsiScanBuffer, AmsiInitialize, and WLDP."""

    def setUp(self):
        self.detector = PowerShellAmsiEtwDetector()

    def test_detect_amsi_scan_buffer_classic_patch(self):
        script = """
        $LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
        $Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
        $p = 0
        [Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
        $Patch = [Byte[]] (0xc3)
        [System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 1)
        """
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "AMSI-MEM-001" for f in findings))
        self.assertTrue(self.detector.has_amsi_bypass(script))
        self.assertTrue(self.detector.has_bypass(script))

        target_finding = [f for f in findings if f.signature_id == "AMSI-MEM-001"][0]
        self.assertEqual(target_finding.target_symbol, "AmsiScanBuffer")
        self.assertEqual(target_finding.severity, BypassSeverity.CRITICAL)
        self.assertEqual(target_finding.category, BypassCategory.MEMORY_PATCH)

    def test_detect_amsi_scan_buffer_byte_variants(self):
        # 0x31, 0xC0, 0xC3 (xor eax, eax; ret)
        script_xor = """
        $a = [Win32]::GetProcAddress([Win32]::LoadLibrary("amsi.dll"), "AmsiScanBuffer")
        [Win32]::VirtualProtect($a, 3, 0x40, [ref]$old)
        [Runtime.InteropServices.Marshal]::Copy([byte[]](0x31, 0xc0, 0xc3), 0, $a, 3)
        """
        findings = self.detector.detect(script_xor)
        self.assertTrue(any(f.signature_id == "AMSI-MEM-001" for f in findings))

        # 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 (mov eax, 0x80070057; ret = E_INVALIDARG)
        script_e_invalidarg = """
        $addr = [Kernel32]::GetProcAddress([Kernel32]::LoadLibrary("amsi.dll"), "AmsiScanBuffer")
        [Kernel32]::VirtualProtect($addr, 6, 0x40, [ref]$p)
        $patch = [byte[]](0xb8, 0x57, 0x00, 0x07, 0x80, 0xc3)
        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)
        """
        findings2 = self.detector.detect(script_e_invalidarg)
        self.assertTrue(any(f.signature_id == "AMSI-MEM-001" for f in findings2))

    def test_detect_wldp_memory_patch(self):
        script = """
        $h = [Win32]::LoadLibrary("wldp.dll")
        $p = [Win32]::GetProcAddress($h, "WldpQueryDynamicCodeTrust")
        [Win32]::VirtualProtect($p, 1, 0x40, [ref]$old)
        """
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "WLDP-MEM-001" for f in findings))


class TestEtwMemoryPatchDetection(unittest.TestCase):
    """Verifies memory patch detection against ntdll.dll!EtwEventWrite."""

    def setUp(self):
        self.detector = PowerShellAmsiEtwDetector()

    def test_detect_etw_event_write_patch_ret(self):
        script = """
        $ntdll = [Win32]::LoadLibrary("ntdll.dll")
        $addr = [Win32]::GetProcAddress($ntdll, "EtwEventWrite")
        [Win32]::VirtualProtect($addr, [uint32]5, 0x40, [ref]$p)
        [System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xc3), 0, $addr, 1)
        """
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "ETW-MEM-001" for f in findings))
        self.assertTrue(self.detector.has_etw_bypass(script))

        finding = [f for f in findings if f.signature_id == "ETW-MEM-001"][0]
        self.assertEqual(finding.target_symbol, "EtwEventWrite")
        self.assertEqual(finding.target_system, TargetSystem.ETW)
        self.assertEqual(finding.category, BypassCategory.MEMORY_PATCH)

    def test_detect_etw_event_write_ret_14(self):
        script = """
        $addr = [Win32]::GetProcAddress([Win32]::LoadLibrary("ntdll.dll"), "EtwEventWrite")
        [Win32]::VirtualProtect($addr, 3, 0x40, [ref]$old)
        [System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xc2, 0x14, 0x00), 0, $addr, 3)
        """
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "ETW-MEM-001" for f in findings))


class TestReflectionTamperingDetection(unittest.TestCase):
    """Verifies reflection tampering detection for amsiInitFailed, etwProvider, m_enabled, and cachedGroupPolicySettings."""

    def setUp(self):
        self.detector = PowerShellAmsiEtwDetector()

    def test_detect_amsi_init_failed_classic(self):
        script = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "AMSI-REFL-001" for f in findings))
        f = [f for f in findings if f.signature_id == "AMSI-REFL-001"][0]
        self.assertEqual(f.target_symbol, "amsiInitFailed")
        self.assertEqual(f.severity, BypassSeverity.CRITICAL)

    def test_detect_amsi_init_failed_multiline(self):
        script = """
        $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        $b = $a.GetField('amsiInitFailed', 'NonPublic,Static')
        $b.SetValue($null, $true)
        """
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "AMSI-REFL-001" for f in findings))

    def test_detect_amsi_context_corruption(self):
        script = """
        $type = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        $field = $type.GetField('amsiContext', 'NonPublic,Static')
        $field.SetValue($null, [IntPtr]::Zero)
        """
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "AMSI-REFL-002" for f in findings))

    def test_detect_etw_provider_reflection(self):
        script = """
        $type = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
        $field = $type.GetField('etwProvider', 'NonPublic,Static')
        $field.SetValue($null, $null)
        """
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "ETW-REFL-001" for f in findings))
        f = [f for f in findings if f.signature_id == "ETW-REFL-001"][0]
        self.assertEqual(f.target_symbol, "etwProvider")

    def test_detect_m_enabled_reflection(self):
        script = """
        $provider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null)
        $field = [System.Diagnostics.Eventing.EventProvider].GetField('m_enabled', [System.Reflection.BindingFlags]'NonPublic, Instance')
        $field.SetValue($provider, 0)
        """
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "ETW-REFL-002" for f in findings))
        f = [f for f in findings if f.signature_id == "ETW-REFL-002"][0]
        self.assertEqual(f.target_symbol, "m_enabled")

    def test_detect_cached_group_policy_settings_tampering(self):
        script = """
        $field = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')
        $dict = $field.GetValue($null)
        $dict['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
        """
        findings = self.detector.detect(script)
        self.assertTrue(any(f.signature_id == "LOG-REFL-001" for f in findings))
        f = [f for f in findings if f.signature_id == "LOG-REFL-001"][0]
        self.assertEqual(f.target_symbol, "cachedGroupPolicySettings")
        self.assertEqual(f.target_system, TargetSystem.SCRIPT_LOGGING)


class TestNeutralizationAndSanitization(unittest.TestCase):
    """Verifies neutralization modes (comment, strip, invert) and preservation of benign code."""

    def setUp(self):
        self.detector = PowerShellAmsiEtwDetector()

    def test_comment_mode_neutralization(self):
        script = (
            "Write-Host 'Starting...'\n"
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
            "Get-Process\n"
        )
        res: SanitizationResult = self.detector.neutralize(script, mode="comment")
        self.assertEqual(res.neutralized_count, 1)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001]", res.sanitized_script)
        self.assertIn("Write-Host 'Starting...'", res.sanitized_script)
        self.assertIn("Get-Process", res.sanitized_script)

    def test_strip_mode_neutralization(self):
        bypass_stmt = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        script = f"Write-Host 'Start'\n{bypass_stmt}\nWrite-Host 'End'"
        res = self.detector.neutralize(script, mode="strip")
        self.assertEqual(res.neutralized_count, 1)
        self.assertNotIn(bypass_stmt, res.sanitized_script)
        self.assertIn("Write-Host 'Start'", res.sanitized_script)
        self.assertIn("Write-Host 'End'", res.sanitized_script)

    def test_invert_mode_neutralization_amsi_init_failed(self):
        script = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        res = self.detector.neutralize(script, mode="invert")
        self.assertEqual(res.neutralized_count, 1)
        self.assertIn("$false", res.sanitized_script)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001] #>", res.sanitized_script)

    def test_neutralize_etw_memory_patch(self):
        script = (
            "$addr = [Win32]::GetProcAddress([Win32]::LoadLibrary('ntdll.dll'), 'EtwEventWrite')\n"
            "[Win32]::VirtualProtect($addr, 5, 0x40, [ref]$p)\n"
            "[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xc3), 0, $addr, 1)\n"
            "Invoke-Expression 'whoami'"
        )
        res = self.detector.neutralize(script)
        self.assertGreaterEqual(res.neutralized_count, 1)
        self.assertIn("Invoke-Expression 'whoami'", res.sanitized_script)
        self.assertIn("<# [NEUTRALIZED: ETW-MEM-001]", res.sanitized_script)

    def test_clean_script_no_modifications(self):
        clean_code = "Get-Service -Name WinDefend | Select-Object Status, DisplayName"
        res = self.detector.neutralize(clean_code)
        self.assertEqual(res.neutralized_count, 0)
        self.assertEqual(res.findings, [])
        self.assertEqual(res.sanitized_script, clean_code)

    def test_functional_convenience_interfaces(self):
        code = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        findings = detect_amsi_etw(code)
        self.assertEqual(len(findings), 1)
        res = neutralize_amsi_etw(code)
        self.assertEqual(res.neutralized_count, 1)


class TestDeobfuscatorEngineIntegration(unittest.TestCase):
    """Verifies integration with PowerShellDeobfuscator multi-pass pipeline."""

    def test_deobfuscator_detects_findings_and_exposes_property(self):
        script = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        engine = PowerShellDeobfuscator(detect_amsi_etw=True)
        res = engine.deobfuscate(script)
        self.assertGreaterEqual(len(engine.last_amsi_etw_findings), 1)
        self.assertEqual(engine.last_amsi_etw_findings[0].signature_id, "AMSI-REFL-001")

    def test_deobfuscator_neutralize_option(self):
        script = (
            "Write-Host 'Hello'\n"
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        )
        engine = PowerShellDeobfuscator(neutralize_amsi_etw=True)
        res = engine.deobfuscate(script)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001]", res)
        self.assertIn("Write-Host 'Hello'", res)

    def test_deobfuscator_unmasks_concatenated_amsi_bypass(self):
        # Concatenated field and type names: ('amsi' + 'Init' + 'Failed')
        script = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(('amsi'+'Init'+'Failed'),'NonPublic,Static').SetValue($null,$true)"
        engine = PowerShellDeobfuscator(detect_amsi_etw=True)
        deobf = engine.deobfuscate(script)
        self.assertIn("amsiInitFailed", deobf)
        self.assertTrue(any(f.signature_id == "AMSI-REFL-001" for f in engine.last_amsi_etw_findings))


class TestCLIIntegration(unittest.TestCase):
    """Verifies CLI flags: --amsi-signatures, --detect-amsi, --neutralize-amsi."""

    def test_cli_amsi_signatures_dump(self):
        with patch("sys.argv", ["pwsh-ast", "--amsi-signatures"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                main()
                output = mock_out.getvalue()
                data = json.loads(output)
                self.assertIsInstance(data, list)
                ids = [s["id"] for s in data]
                self.assertIn("AMSI-MEM-001", ids)
                self.assertIn("ETW-MEM-001", ids)

    def test_cli_detect_amsi_flag(self):
        bypass_code = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        with patch("sys.argv", ["pwsh-ast", bypass_code, "--detect-amsi"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                main()
                output = mock_out.getvalue()
                data = json.loads(output)
                self.assertTrue(data["has_bypass"])
                self.assertGreaterEqual(data["total_findings"], 1)
                self.assertEqual(data["findings"][0]["signature_id"], "AMSI-REFL-001")

    def test_cli_neutralize_amsi_flag(self):
        bypass_code = (
            "Write-Host 'Run'; "
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        )
        with patch("sys.argv", ["pwsh-ast", bypass_code, "--neutralize-amsi"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                main()
                output = mock_out.getvalue()
                self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001]", output)
                self.assertIn("Write-Host", output)



class TestAdversarialAndEdgeCases(unittest.TestCase):
    """Verifies edge cases, multi-command chained pipelines, AST traversal, and hybrid bypasses."""

    def setUp(self):
        self.detector = PowerShellAmsiEtwDetector()

    def test_amsi_initialize_memory_patch(self):
        script = """
        $h = [Win32]::LoadLibrary("amsi.dll")
        $p = [Win32]::GetProcAddress($h, "AmsiInitialize")
        [Win32]::VirtualProtect($p, 1, 0x40, [ref]$old)
        [System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xc3), 0, $p, 1)
        """
        findings = self.detector.detect(script)
        sig_ids = [f.signature_id for f in findings]
        self.assertIn("AMSI-MEM-002", sig_ids)

    def test_amsi_open_session_memory_patch(self):
        script = """
        $h = [Win32]::LoadLibrary("amsi.dll")
        $p = [Win32]::GetProcAddress($h, "AmsiOpenSession")
        [Win32]::VirtualProtect($p, 1, 0x40, [ref]$old)
        """
        findings = self.detector.detect(script)
        sig_ids = [f.signature_id for f in findings]
        self.assertIn("AMSI-MEM-002", sig_ids)

    def test_etw_event_write_transfer_patch(self):
        script = """
        $nt = [Win32]::LoadLibrary("ntdll.dll")
        $p = [Win32]::GetProcAddress($nt, "EtwEventWriteTransfer")
        [Win32]::VirtualProtect($p, 1, 0x40, [ref]$old)
        """
        findings = self.detector.detect(script)
        sig_ids = [f.signature_id for f in findings]
        self.assertIn("ETW-MEM-002", sig_ids)

    def test_semicolon_chained_bypass_with_benign_code(self):
        script = "$x = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); Write-Host 'KEEP THIS CODE'"
        res = self.detector.neutralize(script, mode="comment")
        self.assertIn("Write-Host 'KEEP THIS CODE'", res.sanitized_script)
        self.assertFalse(res.sanitized_script.endswith("#>"))

    def test_chained_multiple_bypasses_on_single_line(self):
        script = "$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); $b = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').SetValue($null,$null)"
        findings = self.detector.detect(script)
        sig_ids = [f.signature_id for f in findings]
        self.assertIn("AMSI-REFL-001", sig_ids)
        self.assertIn("ETW-REFL-001", sig_ids)

        res = self.detector.neutralize(script, mode="comment")
        self.assertEqual(res.neutralized_count, 2)
        self.assertNotIn("<# <#", res.sanitized_script)
        self.assertNotIn("#> #>", res.sanitized_script)

    def test_detect_ast_method_call_chain(self):
        from src.lexer import PowerShellLexer
        from src.parser import PowerShellParser
        script = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        tokens = PowerShellLexer(script).tokenize()
        ast = PowerShellParser(tokens).parse()
        findings = self.detector.detect_ast(ast)
        sig_ids = [f.signature_id for f in findings]
        self.assertIn("AMSI-REFL-001", sig_ids)

    def test_hybrid_amsi_and_etw_memory_patches(self):
        script = """
        $h1 = [Win32]::LoadLibrary("amsi.dll")
        $a1 = [Win32]::GetProcAddress($h1, "AmsiScanBuffer")
        [Win32]::VirtualProtect($a1, 1, 0x40, [ref]$p)
        [System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xc3), 0, $a1, 1)

        $h2 = [Win32]::LoadLibrary("ntdll.dll")
        $a2 = [Win32]::GetProcAddress($h2, "EtwEventWrite")
        [Win32]::VirtualProtect($a2, 1, 0x40, [ref]$p)
        [System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xc3), 0, $a2, 1)
        """
        findings = self.detector.detect(script)
        sig_ids = [f.signature_id for f in findings]
        self.assertIn("AMSI-MEM-001", sig_ids)
        self.assertIn("ETW-MEM-001", sig_ids)

        res = self.detector.neutralize(script, mode="comment")
        self.assertNotIn("#> #>", res.sanitized_script)
        self.assertNotIn("<# [NEUTRALIZED: AMSI-MEM-001] <#", res.sanitized_script)

    def test_comment_with_bypass_keywords_not_flagged(self):
        script = (
            "# Note: We should monitor for amsiInitFailed and AmsiScanBuffer\n"
            "<#\n"
            "This block comment discusses EtwEventWrite and cachedGroupPolicySettings.\n"
            "#>\n"
            "Write-Host 'Harmless script execution'"
        )
        findings = self.detector.detect(script)
        self.assertEqual(findings, [])
        self.assertFalse(self.detector.has_bypass(script))
        res = self.detector.neutralize(script, mode="comment")
        self.assertEqual(res.neutralized_count, 0)
        self.assertEqual(res.sanitized_script, script)

    def test_neutralization_is_idempotent(self):
        script = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        res1 = self.detector.neutralize(script, mode="comment")
        self.assertEqual(res1.neutralized_count, 1)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001]", res1.sanitized_script)

        # Re-detecting sanitized script must report NO findings
        self.assertFalse(self.detector.has_bypass(res1.sanitized_script))
        self.assertEqual(self.detector.detect(res1.sanitized_script), [])

        # Re-neutralizing must be completely idempotent and produce no nested comments
        res2 = self.detector.neutralize(res1.sanitized_script, mode="comment")
        self.assertEqual(res2.neutralized_count, 0)
        self.assertEqual(res2.sanitized_script, res1.sanitized_script)
        self.assertNotIn("< #", res2.sanitized_script)
        self.assertNotIn("# >", res2.sanitized_script)

    def test_inline_comment_does_not_flag_benign_code(self):
        script = "$x = 1 # We must check amsiInitFailed\n$y = 2"
        findings = self.detector.detect(script)
        self.assertEqual(findings, [])
        res = self.detector.neutralize(script, mode="comment")
        self.assertEqual(res.neutralized_count, 0)
        self.assertEqual(res.sanitized_script, script)

    def test_innocent_m_enabled_variable_not_flagged(self):
        script = "$m_enabled = $true\n$config = [PSCustomObject]@{ m_enabled = 1 }"
        findings = self.detector.detect(script)
        self.assertEqual(findings, [])
        self.assertFalse(self.detector.has_etw_bypass(script))

    def test_logging_commands_not_flagged(self):
        script = (
            "Write-Host 'AMSI scan buffer status is normal'\n"
            "Write-Output 'EtwEventWrite event delivery healthy'\n"
            "Write-Verbose 'amsiInitFailed check passed'"
        )
        findings = self.detector.detect(script)
        self.assertEqual(findings, [])

    def test_multiline_reflection_with_intermediate_statements(self):
        script = (
            "$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')\n"
            "Write-Host 'Preparing injection...'\n"
            "$a.SetValue($null, $true)\n"
            "Write-Host 'Done'"
        )
        findings = self.detector.detect(script)
        self.assertEqual(len(findings), 2)
        res = self.detector.neutralize(script, mode="comment")
        self.assertEqual(res.neutralized_count, 2)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001] $a =", res.sanitized_script)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001] $a.SetValue", res.sanitized_script)
        self.assertIn("Write-Host 'Preparing injection...'", res.sanitized_script)
        self.assertIn("Write-Host 'Done'", res.sanitized_script)

    def test_multiline_m_enabled_neutralization_and_inversion(self):
        script = (
            "$provider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null)\n"
            "$field = [System.Diagnostics.Eventing.EventProvider].GetField('m_enabled', [System.Reflection.BindingFlags]'NonPublic, Instance')\n"
            "$field.SetValue($provider, 0)"
        )
        findings = self.detector.detect(script)
        sig_ids = [f.signature_id for f in findings]
        self.assertIn("ETW-REFL-001", sig_ids)
        self.assertIn("ETW-REFL-002", sig_ids)

        # Verify invert mode inverts 0 to 1 on SetValue
        res_inv = self.detector.neutralize(script, mode="invert")
        self.assertIn("$field.SetValue($provider, 1)", res_inv.sanitized_script)

        # Verify comment mode comments out the SetValue
        res_com = self.detector.neutralize(script, mode="comment")
        self.assertIn("<# [NEUTRALIZED: ETW-REFL-002] $field.SetValue", res_com.sanitized_script)

    def test_scriptblock_control_flow_code_preservation(self):
        script = (
            "if ($bypassActive) {\n"
            "    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
            "    Write-Host 'Critical benign business logic'\n"
            "}"
        )
        res = self.detector.neutralize(script, mode="comment")
        self.assertIn("Write-Host 'Critical benign business logic'", res.sanitized_script)
        self.assertIn("if ($bypassActive) {", res.sanitized_script)
        self.assertTrue(res.sanitized_script.strip().endswith("}"))

    def test_detect_ast_constant_folding(self):
        from src.lexer import PowerShellLexer
        from src.parser import PowerShellParser
        script = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(('amsi'+'Init'+'Failed'),'NonPublic,Static').SetValue($null,$true)"
        ast = PowerShellParser(PowerShellLexer(script).tokenize()).parse()
        findings = self.detector.detect_ast(ast)
        self.assertTrue(any(f.signature_id == "AMSI-REFL-001" for f in findings))

    def test_deobfuscator_neutralize_mode_strip_and_invert(self):
        script = (
            "Write-Host 'Header'\n"
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
            "Write-Host 'Footer'"
        )
        # Strip mode
        engine_strip = PowerShellDeobfuscator(neutralize_amsi_etw=True, neutralize_amsi_mode="strip")
        res_strip = engine_strip.deobfuscate(script)
        self.assertNotIn("amsiInitFailed", res_strip)
        self.assertIn("Write-Host 'Header'", res_strip)
        self.assertIn("Write-Host 'Footer'", res_strip)

        # Invert mode
        engine_inv = PowerShellDeobfuscator(neutralize_amsi_etw=True, neutralize_amsi_mode="invert")
        res_inv = engine_inv.deobfuscate(script)
        self.assertIn("$false", res_inv)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001] #>", res_inv)

    def test_braced_variable_amsi_init_failed(self):
        code = "${amsiInitFailed} = $true"
        findings = self.detector.detect(code)
        self.assertTrue(any(f.signature_id == "AMSI-REFL-001" for f in findings))
        res = self.detector.neutralize(code, mode="comment")
        self.assertNotIn("#>} = $true", res.sanitized_script)
        self.assertFalse(res.sanitized_script.endswith("} = $true"))
        self.assertEqual(res.sanitized_script, "<# [NEUTRALIZED: AMSI-REFL-001] ${amsiInitFailed} = $true #>")

    def test_single_line_hashtable_with_bypass(self):
        code = "$dict = @{ amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true) }"
        res = self.detector.neutralize(code, mode="comment")
        self.assertFalse(res.sanitized_script.endswith("#> }"))
        self.assertNotIn("#> }", res.sanitized_script)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001] $dict = @{ amsi =", res.sanitized_script)

    def test_multiline_hashtable_with_bypass(self):
        code = """$dict = @{
    amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    foo = 123
}"""
        res = self.detector.neutralize(code, mode="comment")
        self.assertIn("$dict = @{", res.sanitized_script)
        self.assertIn("foo = 123", res.sanitized_script)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001] amsi =", res.sanitized_script)

    def test_multiple_write_byte_statements(self):
        code = """$a = [Win32]::GetProcAddress($h, "AmsiScanBuffer")
[Win32]::VirtualProtect($a, 3, 0x40, [ref]$old)
[System.Runtime.InteropServices.Marshal]::WriteByte($a, 0x31)
[System.Runtime.InteropServices.Marshal]::WriteByte($a + 1, 0xc0)
[System.Runtime.InteropServices.Marshal]::WriteByte($a + 2, 0xc3)
"""
        findings = self.detector.detect(code)
        matched = [f.matched_text for f in findings]
        self.assertTrue(any("0x31" in m for m in matched))
        self.assertTrue(any("0xc0" in m for m in matched))
        self.assertTrue(any("0xc3" in m for m in matched))

    def test_multiple_gp_settings_assignments(self):
        code = """$field = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')
$dict = $field.GetValue($null)
$dict['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
$dict['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
"""
        findings = self.detector.detect(code)
        matched = [f.matched_text for f in findings]
        self.assertTrue(any("EnableScriptBlockInvocationLogging" in m for m in matched))

    def test_if_condition_with_bypass_and_else(self):
        code = """if ([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)) {
    Write-Host 'bypassed'
} else {
    Write-Host 'fallback'
}"""
        res = self.detector.neutralize(code, mode="comment")
        self.assertNotIn("#> {\n    Write-Host 'bypassed'\n} else", res.sanitized_script)
        self.assertIn("<# [NEUTRALIZED: AMSI-REFL-001] if ([Ref].Assembly", res.sanitized_script)
        self.assertTrue(res.sanitized_script.strip().endswith("#>"))


if __name__ == "__main__":
    unittest.main()

