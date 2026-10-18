"""
PowerShell ExecutionPolicy Public Facade & Reporting Engine.
Provides high-level APIs for policy simulation, bypass detection, neutralization,
and structured reporting (Text & JSON).
"""

import json
from typing import Any, Dict, List, Optional, Tuple, Union

from .policy_models import (
    BypassTechnique,
    ExecutionPolicyLevel,
    PolicyFinding,
    PolicyScope,
    PolicySeverity,
    PolicySimulationSummary,
    PolicyTransition,
    ScopeState,
)
from .policy_reducer import PowerShellPolicyReducer
from .policy_simulator import PowerShellPolicySimulator


def simulate_execution_policy(
    script_text: str,
    baseline_policy: str = "Restricted",
    machine_policy: Optional[str] = None,
    user_policy: Optional[str] = None,
    process_policy: Optional[str] = None,
    current_user_policy: Optional[str] = None,
    local_machine_policy: Optional[str] = None,
) -> PolicySimulationSummary:
    """
    Simulates runtime execution policy state machine across all 5 scopes.
    """
    base_lvl = ExecutionPolicyLevel.from_str(baseline_policy)
    mach_lvl = ExecutionPolicyLevel.from_str(machine_policy) if machine_policy else ExecutionPolicyLevel.UNDEFINED
    user_lvl = ExecutionPolicyLevel.from_str(user_policy) if user_policy else ExecutionPolicyLevel.UNDEFINED
    proc_lvl = ExecutionPolicyLevel.from_str(process_policy) if process_policy else ExecutionPolicyLevel.UNDEFINED
    cu_lvl = ExecutionPolicyLevel.from_str(current_user_policy) if current_user_policy else ExecutionPolicyLevel.UNDEFINED
    lm_lvl = ExecutionPolicyLevel.from_str(local_machine_policy) if local_machine_policy else ExecutionPolicyLevel.UNDEFINED

    simulator = PowerShellPolicySimulator(
        baseline_policy=base_lvl,
        machine_policy=mach_lvl,
        user_policy=user_lvl,
        process_policy=proc_lvl,
        current_user_policy=cu_lvl,
        local_machine_policy=lm_lvl,
    )
    return simulator.simulate(script_text)


def detect_policy_bypasses(script_text: str) -> List[PolicyFinding]:
    """Scans script and returns all identified execution policy bypass findings."""
    summary = simulate_execution_policy(script_text)
    return summary.findings


def parse_cli_policy_args(command_line: str) -> Dict[str, Any]:
    """Parses execution policy flags and parameters from a command-line string."""
    simulator = PowerShellPolicySimulator()
    return simulator.parse_cli_args(command_line)


def neutralize_policy_bypasses(
    script_text: str, mode: str = "comment"
) -> Tuple[str, List[Dict[str, Any]]]:
    """Neutralizes detected policy bypasses according to mode (comment, strip, invert)."""
    findings = detect_policy_bypasses(script_text)
    reducer = PowerShellPolicyReducer(mode=mode)
    return reducer.neutralize(script_text, findings)


def to_policy_report(summary: PolicySimulationSummary) -> str:
    """Renders human-readable policy simulation report."""
    lines = [
        "=" * 72,
        "   POWERSHELL EXECUTION POLICY SIMULATION & FORENSIC REPORT",
        "=" * 72,
        "",
        f"[-] Initial Effective Policy : {summary.initial_effective.value}",
        f"[+] Final Effective Policy   : {summary.final_effective.value}",
        f"[*] Bypass Detected          : {'YES' if summary.bypass_detected else 'NO'}",
        f"[*] Privilege Escalation Risk: {'HIGH/CRITICAL' if summary.privilege_escalation_risk else 'NONE'}",
        f"[*] Threat Risk Score        : {summary.risk_score} / 100 ({summary.risk_level})",
        "",
        "--- SCOPE CONFIGURATION MATRIX ---",
        f"  * MachinePolicy (GPO) : {summary.final_state.machine_policy.value}",
        f"  * UserPolicy (GPO)    : {summary.final_state.user_policy.value}",
        f"  * Process (Session)   : {summary.final_state.process.value}",
        f"  * CurrentUser (HKCU)  : {summary.final_state.current_user.value}",
        f"  * LocalMachine (HKLM) : {summary.final_state.local_machine.value}",
        f"  * Default Fallback    : {summary.final_state.default_policy.value}",
        f"  => Winning Active Scope: {summary.final_state.effective_policy()[1]}",
        "",
    ]

    if summary.transitions:
        lines.append("--- POLICY STATE TRANSITIONS ---")
        for t in summary.transitions:
            status = "[BLOCKED BY GPO]" if t.blocked_by_gpo else "[TRANSITION APPLIED]"
            lines.append(f"  Step {t.step} | {t.technique.value:<22} | {status}")
            lines.append(f"    Statement : {t.statement_snippet}")
            lines.append(f"    Transition: {t.previous_level.value} ({t.previous_winning_scope}) -> {t.new_level.value} ({t.new_winning_scope})")
            lines.append("")

    if summary.findings:
        lines.append(f"--- DETECTED FINDINGS ({len(summary.findings)}) ---")
        for idx, f in enumerate(summary.findings, 1):
            admin_tag = " [REQUIRES ELEVATION]" if f.requires_admin else ""
            gpo_tag = " [OVERRIDDEN BY GPO]" if f.blocked_by_gpo else ""
            lines.append(f"  [{idx}] {f.severity.value} - {f.technique.value}{admin_tag}{gpo_tag}")
            lines.append(f"      Line {f.line_number} (Statement {f.statement_index})")
            lines.append(f"      Target: {f.target_level.value} on {f.target_scope.value if f.target_scope else 'N/A'}")
            lines.append(f"      Code  : {f.matched_text}")
            lines.append(f"      Detail: {f.description}")
            if f.mitigation:
                lines.append(f"      Remedy: {f.mitigation}")
            lines.append("")
    else:
        lines.append("--- NO EXECUTION POLICY BYPASSES DETECTED ---")
        lines.append("")

    if summary.mitigations:
        lines.append("--- RECOMMENDED MITIGATIONS ---")
        for m in summary.mitigations:
            lines.append(f"  * {m}")
        lines.append("")

    lines.append("=" * 72)
    return "\n".join(lines)


def export_policy_json(summary: PolicySimulationSummary, indent: int = 2) -> str:
    """Exports structured simulation report as formatted JSON."""
    return json.dumps(summary.to_dict(), indent=indent, ensure_ascii=False)
