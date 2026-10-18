"""
Comprehensive Test Suite for PowerShell ExecutionPolicy Simulation & Bypass Analysis Engine.
Validates multi-scope precedence rules, CLI flag parsing, environment variable tampering,
cmdlet invocations, in-memory reflection, ADS zone stripping, neutralization, and reporting.
"""

import json
import unittest

from src.execution_policy import (
    BypassTechnique,
    ExecutionPolicyLevel,
    PolicyFinding,
    PolicyScope,
    PolicySeverity,
    PowerShellPolicyReducer,
    PowerShellPolicySimulator,
    detect_policy_bypasses,
    export_policy_json,
    neutralize_policy_bypasses,
    parse_cli_policy_args,
    simulate_execution_policy,
    to_policy_report,
)
from src.deobfuscator_engine import PowerShellDeobfuscator


class TestExecutionPolicyModels(unittest.TestCase):
    """Tests core ExecutionPolicy enums, levels, scopes, and precedence resolution."""

    def test_level_parsing_and_aliases(self):
        self.assertEqual(ExecutionPolicyLevel.from_str("restricted"), ExecutionPolicyLevel.RESTRICTED)
        self.assertEqual(ExecutionPolicyLevel.from_str("AllSigned"), ExecutionPolicyLevel.ALL_SIGNED)
        self.assertEqual(ExecutionPolicyLevel.from_str("remotesigned"), ExecutionPolicyLevel.REMOTE_SIGNED)
        self.assertEqual(ExecutionPolicyLevel.from_str("Unrestricted"), ExecutionPolicyLevel.UNRESTRICTED)
        self.assertEqual(ExecutionPolicyLevel.from_str("BYPASS"), ExecutionPolicyLevel.BYPASS)
        self.assertEqual(ExecutionPolicyLevel.from_str("bp"), ExecutionPolicyLevel.BYPASS)
        self.assertEqual(ExecutionPolicyLevel.from_str("none"), ExecutionPolicyLevel.BYPASS)
        self.assertEqual(ExecutionPolicyLevel.from_str("unknown_garbage"), ExecutionPolicyLevel.UNDEFINED)

    def test_level_permissiveness_and_permissions(self):
        self.assertTrue(ExecutionPolicyLevel.BYPASS.is_permissive())
        self.assertTrue(ExecutionPolicyLevel.UNRESTRICTED.is_permissive())
        self.assertFalse(ExecutionPolicyLevel.REMOTE_SIGNED.is_permissive())
        self.assertFalse(ExecutionPolicyLevel.RESTRICTED.is_permissive())

        # Allows script logic
        self.assertTrue(ExecutionPolicyLevel.BYPASS.allows_script(is_remote=True, is_signed=False))
        self.assertTrue(ExecutionPolicyLevel.UNRESTRICTED.allows_script(is_remote=True, is_signed=False))
        self.assertTrue(ExecutionPolicyLevel.REMOTE_SIGNED.allows_script(is_remote=False, is_signed=False))
        self.assertFalse(ExecutionPolicyLevel.REMOTE_SIGNED.allows_script(is_remote=True, is_signed=False))
        self.assertTrue(ExecutionPolicyLevel.REMOTE_SIGNED.allows_script(is_remote=True, is_signed=True))
        self.assertFalse(ExecutionPolicyLevel.ALL_SIGNED.allows_script(is_remote=False, is_signed=False))
        self.assertTrue(ExecutionPolicyLevel.ALL_SIGNED.allows_script(is_remote=False, is_signed=True))
        self.assertFalse(ExecutionPolicyLevel.RESTRICTED.allows_script(is_remote=False, is_signed=True))

    def test_scope_precedence_and_elevation(self):
        self.assertEqual(PolicyScope.from_str("machinepolicy"), PolicyScope.MACHINE_POLICY)
        self.assertEqual(PolicyScope.from_str("Process"), PolicyScope.PROCESS)
        self.assertEqual(PolicyScope.from_str("proc"), PolicyScope.PROCESS)
        self.assertEqual(PolicyScope.from_str("CurrentUser"), PolicyScope.CURRENT_USER)
        self.assertEqual(PolicyScope.from_str("LocalMachine"), PolicyScope.LOCAL_MACHINE)

        # Precedence check: MachinePolicy > UserPolicy > Process > CurrentUser > LocalMachine
        self.assertGreater(PolicyScope.MACHINE_POLICY.precedence, PolicyScope.USER_POLICY.precedence)
        self.assertGreater(PolicyScope.USER_POLICY.precedence, PolicyScope.PROCESS.precedence)
        self.assertGreater(PolicyScope.PROCESS.precedence, PolicyScope.CURRENT_USER.precedence)
        self.assertGreater(PolicyScope.CURRENT_USER.precedence, PolicyScope.LOCAL_MACHINE.precedence)

        self.assertTrue(PolicyScope.MACHINE_POLICY.requires_elevation)
        self.assertTrue(PolicyScope.LOCAL_MACHINE.requires_elevation)
        self.assertFalse(PolicyScope.PROCESS.requires_elevation)
        self.assertFalse(PolicyScope.CURRENT_USER.requires_elevation)


class TestScopePrecedenceMatrix(unittest.TestCase):
    """Tests accurate precedence resolution across all 5 PowerShell execution policy scopes."""

    def test_default_fallback_to_restricted(self):
        sim = PowerShellPolicySimulator(baseline_policy=ExecutionPolicyLevel.RESTRICTED)
        summary = sim.simulate("")
        self.assertEqual(summary.initial_effective, ExecutionPolicyLevel.RESTRICTED)
        self.assertEqual(summary.final_effective, ExecutionPolicyLevel.RESTRICTED)
        eff_lvl, eff_scope = summary.final_state.effective_policy()
        self.assertEqual(eff_lvl, ExecutionPolicyLevel.RESTRICTED)
        self.assertEqual(eff_scope, "Default")

    def test_local_machine_overrides_default(self):
        sim = PowerShellPolicySimulator(
            baseline_policy=ExecutionPolicyLevel.RESTRICTED,
            local_machine_policy=ExecutionPolicyLevel.REMOTE_SIGNED,
        )
        summary = sim.simulate("")
        eff_lvl, eff_scope = summary.final_state.effective_policy()
        self.assertEqual(eff_lvl, ExecutionPolicyLevel.REMOTE_SIGNED)
        self.assertEqual(eff_scope, "LocalMachine")

    def test_current_user_overrides_local_machine(self):
        sim = PowerShellPolicySimulator(
            local_machine_policy=ExecutionPolicyLevel.REMOTE_SIGNED,
            current_user_policy=ExecutionPolicyLevel.UNRESTRICTED,
        )
        summary = sim.simulate("")
        eff_lvl, eff_scope = summary.final_state.effective_policy()
        self.assertEqual(eff_lvl, ExecutionPolicyLevel.UNRESTRICTED)
        self.assertEqual(eff_scope, "CurrentUser")

    def test_process_overrides_current_user(self):
        sim = PowerShellPolicySimulator(
            local_machine_policy=ExecutionPolicyLevel.REMOTE_SIGNED,
            current_user_policy=ExecutionPolicyLevel.RESTRICTED,
            process_policy=ExecutionPolicyLevel.BYPASS,
        )
        summary = sim.simulate("")
        eff_lvl, eff_scope = summary.final_state.effective_policy()
        self.assertEqual(eff_lvl, ExecutionPolicyLevel.BYPASS)
        self.assertEqual(eff_scope, "Process")

    def test_user_policy_gpo_overrides_process(self):
        sim = PowerShellPolicySimulator(
            process_policy=ExecutionPolicyLevel.BYPASS,
            user_policy=ExecutionPolicyLevel.ALL_SIGNED,
        )
        summary = sim.simulate("")
        eff_lvl, eff_scope = summary.final_state.effective_policy()
        self.assertEqual(eff_lvl, ExecutionPolicyLevel.ALL_SIGNED)
        self.assertEqual(eff_scope, "UserPolicy")

    def test_machine_policy_gpo_overrides_all(self):
        sim = PowerShellPolicySimulator(
            process_policy=ExecutionPolicyLevel.BYPASS,
            user_policy=ExecutionPolicyLevel.UNRESTRICTED,
            machine_policy=ExecutionPolicyLevel.RESTRICTED,
        )
        summary = sim.simulate("")
        eff_lvl, eff_scope = summary.final_state.effective_policy()
        self.assertEqual(eff_lvl, ExecutionPolicyLevel.RESTRICTED)
        self.assertEqual(eff_scope, "MachinePolicy")


class TestCLIPolicyParsing(unittest.TestCase):
    """Tests detection of CLI flags, parameter abbreviations, and execution modes."""

    def test_cli_full_flag_bypass(self):
        cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\payload.ps1"
        res = parse_cli_policy_args(cmd)
        self.assertTrue(res["has_policy_flag"])
        self.assertTrue(res["is_bypass"])
        self.assertEqual(res["execution_policy"], ExecutionPolicyLevel.BYPASS)
        self.assertEqual(res["scope"], PolicyScope.PROCESS)
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["findings"][0].technique, BypassTechnique.CLI_FLAG)

    def test_cli_short_flag_ep(self):
        cmd = "pwsh.exe -ep unrestricted -WindowStyle Hidden"
        res = parse_cli_policy_args(cmd)
        self.assertTrue(res["has_policy_flag"])
        self.assertTrue(res["is_bypass"])
        self.assertEqual(res["execution_policy"], ExecutionPolicyLevel.UNRESTRICTED)

    def test_cli_prefix_truncation(self):
        cmd = "powershell -execut bypass -c \"Write-Host pwned\""
        res = parse_cli_policy_args(cmd)
        self.assertTrue(res["has_policy_flag"])
        self.assertEqual(res["execution_policy"], ExecutionPolicyLevel.BYPASS)
        self.assertTrue(res["has_command_flag"])

    def test_cli_encoded_command(self):
        cmd = "powershell.exe -nop -enc SQBFAFgA"
        res = parse_cli_policy_args(cmd)
        self.assertTrue(res["has_encoded_flag"])

    def test_cli_stdin_pipeline(self):
        cmd = "Get-Content script.ps1 | powershell -"
        res = parse_cli_policy_args(cmd)
        self.assertTrue(res["has_stdin_flag"])


class TestScriptBypassDetection(unittest.TestCase):
    """Tests static AST statement scanning for execution policy bypasses."""

    def test_env_var_direct_bypass(self):
        script = "$env:PSExecutionPolicyPreference = 'Bypass'\nWrite-Output 'Running unconstrained'"
        summary = simulate_execution_policy(script)
        self.assertTrue(summary.bypass_detected)
        self.assertEqual(summary.final_effective, ExecutionPolicyLevel.BYPASS)
        self.assertEqual(len(summary.findings), 1)
        finding = summary.findings[0]
        self.assertEqual(finding.technique, BypassTechnique.ENV_VAR)
        self.assertEqual(finding.target_level, ExecutionPolicyLevel.BYPASS)
        self.assertEqual(finding.target_scope, PolicyScope.PROCESS)
        self.assertFalse(finding.requires_admin)

    def test_env_var_method_invocation(self):
        script = "[System.Environment]::SetEnvironmentVariable('PSExecutionPolicyPreference', 'Unrestricted', 'Process')"
        summary = simulate_execution_policy(script)
        self.assertTrue(summary.bypass_detected)
        self.assertEqual(summary.final_effective, ExecutionPolicyLevel.UNRESTRICTED)
        self.assertEqual(len(summary.findings), 1)
        finding = summary.findings[0]
        self.assertEqual(finding.technique, BypassTechnique.ENV_VAR)
        self.assertEqual(finding.target_level, ExecutionPolicyLevel.UNRESTRICTED)

    def test_set_execution_policy_process_scope(self):
        script = "Set-ExecutionPolicy Bypass -Scope Process -Force"
        summary = simulate_execution_policy(script)
        self.assertTrue(summary.bypass_detected)
        self.assertEqual(summary.final_effective, ExecutionPolicyLevel.BYPASS)
        finding = summary.findings[0]
        self.assertEqual(finding.technique, BypassTechnique.CMDLET_SET_POLICY)
        self.assertEqual(finding.target_scope, PolicyScope.PROCESS)
        self.assertFalse(finding.requires_admin)

    def test_set_execution_policy_local_machine_requires_elevation(self):
        script = "Set-ExecutionPolicy Unrestricted -Force"
        summary = simulate_execution_policy(script)
        self.assertTrue(summary.bypass_detected)
        finding = summary.findings[0]
        self.assertEqual(finding.target_scope, PolicyScope.LOCAL_MACHINE)
        self.assertTrue(finding.requires_admin)

    def test_gpo_blocks_process_cmdlet_bypass(self):
        # When MachinePolicy is enforced as Restricted via GPO
        script = "Set-ExecutionPolicy Bypass -Scope Process -Force"
        summary = simulate_execution_policy(script, machine_policy="Restricted")
        self.assertTrue(summary.bypass_detected)
        # Even though script called Set-ExecutionPolicy, effective policy is STILL Restricted due to GPO
        self.assertEqual(summary.final_effective, ExecutionPolicyLevel.RESTRICTED)
        finding = summary.findings[0]
        self.assertTrue(finding.blocked_by_gpo)
        self.assertEqual(len(summary.transitions), 1)
        self.assertTrue(summary.transitions[0].blocked_by_gpo)

    def test_reflection_authorization_manager_tampering(self):
        script = """
        $context = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedContext', 'NonPublic,Static').GetValue($null)
        $context.AuthorizationManager = $null
        """
        summary = simulate_execution_policy(script)
        self.assertTrue(summary.bypass_detected)
        self.assertTrue(summary.privilege_escalation_risk)
        self.assertEqual(summary.risk_level, "CRITICAL")
        self.assertEqual(len(summary.findings), 1)
        finding = summary.findings[0]
        self.assertEqual(finding.technique, BypassTechnique.REFLECTION_AUTH_MGR)
        self.assertEqual(finding.severity, PolicySeverity.CRITICAL)

    def test_ads_zone_identifier_stripping(self):
        script = "Unblock-File -Path .\\downloaded_loader.ps1\nRemove-Item .\\agent.ps1:Zone.Identifier"
        findings = detect_policy_bypasses(script)
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertEqual(f.technique, BypassTechnique.ADS_ZONE_STRIP)
            self.assertEqual(f.severity, PolicySeverity.HIGH)


    def test_registry_direct_tampering(self):
        script = "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell' -Name 'ExecutionPolicy' -Value 'Bypass'"
        summary = simulate_execution_policy(script)
        self.assertTrue(summary.bypass_detected)
        finding = summary.findings[0]
        self.assertEqual(finding.technique, BypassTechnique.REGISTRY_TAMPERING)
        self.assertEqual(finding.target_scope, PolicyScope.CURRENT_USER)


class TestNeutralizationAndReporting(unittest.TestCase):
    """Tests neutralization modes and forensic reporting."""

    def test_neutralize_comment_mode(self):
        script = "$env:PSExecutionPolicyPreference = 'Bypass'\nWrite-Host 'Safe Payload'"
        sanitized, mods = neutralize_policy_bypasses(script, mode="comment")
        self.assertIn("<# [NEUTRALIZED EXECUTION POLICY BYPASS: ENV_VAR]", sanitized)
        self.assertIn("Write-Host 'Safe Payload'", sanitized)
        self.assertEqual(len(mods), 1)

    def test_neutralize_strip_mode(self):
        script = "Set-ExecutionPolicy Bypass -Scope Process -Force\nWrite-Host 'Done'"
        sanitized, mods = neutralize_policy_bypasses(script, mode="strip")
        self.assertNotIn("Set-ExecutionPolicy", sanitized)
        self.assertIn("Write-Host 'Done'", sanitized)

    def test_neutralize_invert_mode(self):
        script = "$env:PSExecutionPolicyPreference = 'Bypass'\nWrite-Host 'Active'"
        sanitized, mods = neutralize_policy_bypasses(script, mode="invert")
        self.assertIn("$env:PSExecutionPolicyPreference = 'Restricted'", sanitized)

    def test_report_generation(self):
        script = "$env:PSExecutionPolicyPreference = 'Bypass'"
        summary = simulate_execution_policy(script)
        report = to_policy_report(summary)
        self.assertIn("POWERSHELL EXECUTION POLICY SIMULATION", report)
        self.assertIn("Initial Effective Policy : Restricted", report)
        self.assertIn("Final Effective Policy   : Bypass", report)
        self.assertIn("Bypass Detected          : YES", report)
        self.assertIn("SCOPE CONFIGURATION MATRIX", report)

    def test_json_export_roundtrip(self):
        script = "Set-ExecutionPolicy Bypass -Scope Process -Force"
        summary = simulate_execution_policy(script)
        json_str = export_policy_json(summary)
        data = json.loads(json_str)
        self.assertTrue(data["bypass_detected"])
        self.assertEqual(data["final_effective"], "Bypass")
        self.assertGreater(data["findings_count"], 0)


class TestDeobfuscatorIntegration(unittest.TestCase):
    """Tests end-to-end integration with PowerShellDeobfuscator and multi-pass pipeline."""

    def test_deobfuscator_policy_simulation(self):
        script = "$env:PSExecutionPolicyPreference = 'Bypass'\n'I'+'EX' ('Write-Host test')"
        engine = PowerShellDeobfuscator(simulate_policy=True)
        result = engine.deobfuscate(script)
        self.assertIsNotNone(engine.last_policy_summary)
        self.assertTrue(engine.last_policy_summary.bypass_detected)
        self.assertEqual(engine.last_policy_summary.final_effective, ExecutionPolicyLevel.BYPASS)
        self.assertIn("IEX", result)

    def test_deobfuscator_policy_neutralization(self):
        script = "Set-ExecutionPolicy Bypass -Scope Process -Force\n'Hello '+'World'"
        engine = PowerShellDeobfuscator(neutralize_policy=True, neutralize_policy_mode="comment")
        result = engine.deobfuscate(script)
        self.assertIn("<# [NEUTRALIZED EXECUTION POLICY BYPASS:", result)
        self.assertIn("'Hello World'", result)

    def test_deobfuscator_get_policy_analysis_method(self):
        engine = PowerShellDeobfuscator()
        summary = engine.get_policy_analysis("Unblock-File .\\sample.ps1")
        self.assertTrue(summary.bypass_detected)
        self.assertEqual(len(summary.findings), 1)


if __name__ == "__main__":
    unittest.main()
