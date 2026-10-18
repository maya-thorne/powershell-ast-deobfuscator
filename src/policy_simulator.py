"""
PowerShell ExecutionPolicy Simulator & Bypass Flag Static Analysis Engine.
Simulates multi-scope precedence rules and identifies evasion techniques across CLI flags,
environment variables, cmdlet calls, in-memory reflection, and ADS zone identifier stripping.
"""

import re
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
from .statement_span_parser import _get_statement_spans, _strip_comments


class PowerShellPolicySimulator:
    """
    Compiler-grade simulator for PowerShell runtime execution policies.
    Models the 5 configuration scopes (MachinePolicy, UserPolicy, Process, CurrentUser, LocalMachine)
    and analyzes script ASTs and CLI invocations for bypass techniques.
    """

    # CLI Parameter prefix regex matching PowerShell parameter truncation rules
    # e.g., -ex, -exec, -execu, -execut, -executionp, -executionpolicy, -ep
    _RE_CLI_EP_FLAG = re.compile(
        r"(?:^|\s)-(?:ep|executionpolicy|execpol|execpolicy|executionp|execut|execu|exec|exe|ex)\b(?:\s*[:=]?\s*|\s+)(['\"]?[A-Za-z]+['\"]?)",
        re.IGNORECASE,
    )

    _RE_CLI_SCOPE_FLAG = re.compile(
        r"(?:^|\s)-(?:scope|sc)\b(?:\s*[:=]?\s*|\s+)(['\"]?[A-Za-z]+['\"]?)",
        re.IGNORECASE,
    )

    _RE_CLI_CMD_FLAG = re.compile(
        r"(?:^|\s)-(?:c|command|comm|comma|comman)\b",
        re.IGNORECASE,
    )

    _RE_CLI_ENC_FLAG = re.compile(
        r"(?:^|\s)-(?:e|enc|encodedcommand|encodedc|encodedcom|encodedcomm)\b",
        re.IGNORECASE,
    )

    # Set-ExecutionPolicy Cmdlet patterns
    _RE_SET_EP_CMDLET = re.compile(
        r"\b(?:Set-ExecutionPolicy|set-ep)\b",
        re.IGNORECASE,
    )

    # Environment variable patterns
    _RE_ENV_VAR_DIRECT = re.compile(
        r"\$env:PSExecutionPolicyPreference\s*=\s*(['\"]?)([A-Za-z]+)\1",
        re.IGNORECASE,
    )

    _RE_ENV_VAR_SET_METHOD = re.compile(
        r"\[(?:System\.)?Environment\]::SetEnvironmentVariable\s*\(\s*['\"]PSExecutionPolicyPreference['\"]\s*,\s*(['\"]?)([A-Za-z]+)\1(?:\s*,\s*(['\"]?)([A-Za-z]+)\3)?\s*\)",
        re.IGNORECASE,
    )

    # Reflection AuthorizationManager tampering patterns
    _RE_AUTH_MGR_TYPE = re.compile(
        r"System\.Management\.Automation\.AuthorizationManager",
        re.IGNORECASE,
    )

    _RE_CACHED_CONTEXT = re.compile(
        r"(?:cachedContext|cachedGroupPolicySettings|AuthorizationManager|_authorizationManager)",
        re.IGNORECASE,
    )

    _RE_AUTH_MGR_OVERWRITE = re.compile(
        r"\.AuthorizationManager\s*=\s*(?:\$null|New-Object|\[|@{)",
        re.IGNORECASE,
    )

    # ADS Zone.Identifier unblocking patterns
    _RE_UNBLOCK_FILE = re.compile(
        r"\b(?:Unblock-File)\b",
        re.IGNORECASE,
    )

    _RE_ZONE_ID_STRIP = re.compile(
        r"(?:Remove-Item|Set-Content|Clear-Content)\s+.*?Zone\.Identifier",
        re.IGNORECASE,
    )

    # Registry direct manipulation
    _RE_REG_EXEC_POLICY = re.compile(
        r"(?:HKCU|HKLM):\\(?:Software\\(?:Policies\\)?Microsoft\\PowerShell\\(?:1\\ShellIds\\Microsoft\.PowerShell)?).*?ExecutionPolicy",
        re.IGNORECASE,
    )

    def __init__(
        self,
        baseline_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.RESTRICTED,
        machine_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED,
        user_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED,
        process_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED,
        current_user_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED,
        local_machine_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED,
    ):
        self.initial_state = ScopeState(
            machine_policy=machine_policy,
            user_policy=user_policy,
            process=process_policy,
            current_user=current_user_policy,
            local_machine=local_machine_policy,
            default_policy=baseline_policy,
        )

    def simulate(self, script_text: str) -> PolicySimulationSummary:
        """
        Executes static simulation over the script text, evaluating statement-by-statement
        state changes, detecting bypass attempts, and computing final effective policy.
        """
        current_state = self.initial_state.clone()
        init_eff_lvl, _ = current_state.effective_policy()
        findings: List[PolicyFinding] = []
        transitions: List[PolicyTransition] = []

        spans = _get_statement_spans(script_text)
        stmt_idx = 0

        for start_pos, end_pos in spans:
            stmt_raw = script_text[start_pos:end_pos].strip()
            if not stmt_raw:
                continue

            stmt_clean = _strip_comments(stmt_raw).strip()
            if not stmt_clean:
                continue

            stmt_idx += 1
            line_num = script_text[:start_pos].count("\n") + 1

            # 1. Environment Variable setting
            env_findings = self._inspect_environment_variable(stmt_clean, stmt_raw, stmt_idx, line_num, current_state)
            if env_findings:
                for finding, target_lvl, target_scp in env_findings:
                    findings.append(finding)
                    transition = self._apply_transition(
                        current_state, target_scp, target_lvl, finding.technique, stmt_raw, stmt_idx
                    )
                    transitions.append(transition)

            # 2. Set-ExecutionPolicy cmdlet call
            cmdlet_findings = self._inspect_cmdlet_invocation(stmt_clean, stmt_raw, stmt_idx, line_num, current_state)
            if cmdlet_findings:
                for finding, target_lvl, target_scp in cmdlet_findings:
                    findings.append(finding)
                    transition = self._apply_transition(
                        current_state, target_scp, target_lvl, finding.technique, stmt_raw, stmt_idx
                    )
                    transitions.append(transition)

            # 3. In-Memory Reflection / AuthorizationManager tampering
            refl_findings = self._inspect_reflection_tampering(stmt_clean, stmt_raw, stmt_idx, line_num, current_state)
            if refl_findings:
                for finding in refl_findings:
                    findings.append(finding)
                    # Reflection effectively unlocks the process entirely, bypassing even GPO
                    transition = self._apply_transition(
                        current_state, PolicyScope.PROCESS, ExecutionPolicyLevel.BYPASS, finding.technique, stmt_raw, stmt_idx, forced=True
                    )
                    transitions.append(transition)

            # 4. ADS Zone.Identifier Stripping
            ads_findings = self._inspect_zone_identifier(stmt_clean, stmt_raw, stmt_idx, line_num)
            for finding in ads_findings:
                findings.append(finding)

            # 5. Registry direct tampering
            reg_findings = self._inspect_registry_tampering(stmt_clean, stmt_raw, stmt_idx, line_num, current_state)
            if reg_findings:
                for finding, target_lvl, target_scp in reg_findings:
                    findings.append(finding)
                    transition = self._apply_transition(
                        current_state, target_scp, target_lvl, finding.technique, stmt_raw, stmt_idx
                    )
                    transitions.append(transition)

        # Also inspect for nested/embedded CLI invocations in the entire script
        cli_findings = self._inspect_embedded_cli(script_text, current_state)
        for finding in cli_findings:
            findings.append(finding)

        final_eff_lvl, _ = current_state.effective_policy()
        bypass_detected = len(findings) > 0 or final_eff_lvl.is_permissive()
        privilege_escalation = any(f.requires_admin or f.technique == BypassTechnique.REFLECTION_AUTH_MGR for f in findings)
        if not privilege_escalation and init_eff_lvl in (ExecutionPolicyLevel.RESTRICTED, ExecutionPolicyLevel.ALL_SIGNED):
            if final_eff_lvl in (ExecutionPolicyLevel.BYPASS, ExecutionPolicyLevel.UNRESTRICTED):
                privilege_escalation = True

        risk_score, risk_level = self._calculate_risk_metrics(findings, init_eff_lvl, final_eff_lvl)
        mitigations = self._generate_mitigations(findings, current_state)

        return PolicySimulationSummary(
            initial_state=self.initial_state.clone(),
            final_state=current_state,
            initial_effective=init_eff_lvl,
            final_effective=final_eff_lvl,
            bypass_detected=bypass_detected,
            privilege_escalation_risk=privilege_escalation,
            findings=findings,
            transitions=transitions,
            risk_score=risk_score,
            risk_level=risk_level,
            mitigations=mitigations,
        )

    def parse_cli_args(self, command_line: str) -> Dict[str, Any]:
        """
        Parses CLI command string (e.g. `powershell.exe -ExecutionPolicy Bypass -NoProfile ...`)
        and extracts policy flags, target levels, and command-line execution modes.
        """
        result: Dict[str, Any] = {
            "execution_policy": ExecutionPolicyLevel.UNDEFINED,
            "scope": PolicyScope.PROCESS,
            "has_policy_flag": False,
            "is_bypass": False,
            "has_command_flag": False,
            "has_encoded_flag": False,
            "has_stdin_flag": False,
            "findings": [],
        }

        # Check for execution policy flag
        ep_match = self._RE_CLI_EP_FLAG.search(command_line)
        if ep_match:
            raw_val = ep_match.group(1).strip("'\"")
            level = ExecutionPolicyLevel.from_str(raw_val)
            result["execution_policy"] = level
            result["has_policy_flag"] = True
            result["is_bypass"] = level.is_permissive()

            scope = PolicyScope.PROCESS
            scope_match = self._RE_CLI_SCOPE_FLAG.search(command_line)
            if scope_match:
                parsed_scope = PolicyScope.from_str(scope_match.group(1).strip("'\""))
                if parsed_scope:
                    scope = parsed_scope
            result["scope"] = scope

            finding = PolicyFinding(
                technique=BypassTechnique.CLI_FLAG,
                severity=PolicySeverity.HIGH if level.is_permissive() else PolicySeverity.LOW,
                target_level=level,
                target_scope=scope,
                description=f"PowerShell CLI launched with explicit -ExecutionPolicy {level.value} flag",
                statement_index=0,
                line_number=1,
                matched_text=ep_match.group(0).strip(),
                requires_admin=scope.requires_elevation,
                mitigation="Enforce execution policy through Group Policy (MachinePolicy) which overrides CLI arguments.",
            )
            result["findings"].append(finding)

        # Check for command flag
        if self._RE_CLI_CMD_FLAG.search(command_line):
            result["has_command_flag"] = True
            finding = PolicyFinding(
                technique=BypassTechnique.COMMAND_ARG,
                severity=PolicySeverity.MEDIUM,
                target_level=ExecutionPolicyLevel.BYPASS,
                target_scope=PolicyScope.PROCESS,
                description="PowerShell CLI launched with -Command / -c argument (bypasses script file policy enforcement)",
                statement_index=0,
                line_number=1,
                matched_text="-Command",
                mitigation="Enable ScriptBlock Logging (EID 4104) and Constrained Language Mode to inspect in-memory command blocks.",
            )
            result["findings"].append(finding)

        # Check for encoded command
        if self._RE_CLI_ENC_FLAG.search(command_line):
            result["has_encoded_flag"] = True
            finding = PolicyFinding(
                technique=BypassTechnique.ENCODED_COMMAND,
                severity=PolicySeverity.HIGH,
                target_level=ExecutionPolicyLevel.BYPASS,
                target_scope=PolicyScope.PROCESS,
                description="PowerShell CLI launched with -EncodedCommand argument",
                statement_index=0,
                line_number=1,
                matched_text="-EncodedCommand",
                mitigation="Enforce PowerShell ScriptBlock Logging (EID 4104) to log decoded payload content.",
            )
            result["findings"].append(finding)

        # Check for stdin redirection
        if re.search(r"(?:^|\s)-(?:\s*$|\s+[^\-])", command_line) or "powershell -" in command_line.lower():
            result["has_stdin_flag"] = True
            finding = PolicyFinding(
                technique=BypassTechnique.STDIN_PIPELINE,
                severity=PolicySeverity.MEDIUM,
                target_level=ExecutionPolicyLevel.BYPASS,
                target_scope=PolicyScope.PROCESS,
                description="PowerShell CLI reading script payload via standard input pipeline (stdin)",
                statement_index=0,
                line_number=1,
                matched_text="powershell -",
                mitigation="Audit process creation and command line parameters for stdin redirection patterns.",
            )
            result["findings"].append(finding)

        return result

    # --- Private Inspection Helpers ---

    def _inspect_environment_variable(
        self, stmt_clean: str, stmt_raw: str, stmt_idx: int, line_num: int, state: ScopeState
    ) -> List[Tuple[PolicyFinding, ExecutionPolicyLevel, PolicyScope]]:
        results = []
        # Pattern 1: $env:PSExecutionPolicyPreference = '...'
        m1 = self._RE_ENV_VAR_DIRECT.search(stmt_clean)
        if m1:
            raw_val = m1.group(2)
            level = ExecutionPolicyLevel.from_str(raw_val)
            scope = PolicyScope.PROCESS
            blocked = state.is_scope_blocked_by_gpo(scope)
            finding = PolicyFinding(
                technique=BypassTechnique.ENV_VAR,
                severity=PolicySeverity.HIGH if level.is_permissive() else PolicySeverity.LOW,
                target_level=level,
                target_scope=scope,
                description=f"Direct modification of $env:PSExecutionPolicyPreference to {level.value}",
                statement_index=stmt_idx,
                line_number=line_num,
                matched_text=m1.group(0),
                requires_admin=False,
                blocked_by_gpo=blocked,
                mitigation="Group Policy (MachinePolicy) overrides process-level environment variable preference.",
            )
            results.append((finding, level, scope))

        # Pattern 2: [Environment]::SetEnvironmentVariable(...)
        m2 = self._RE_ENV_VAR_SET_METHOD.search(stmt_clean)
        if m2:
            raw_val = m2.group(2)
            raw_scope = m2.group(4) or "Process"
            level = ExecutionPolicyLevel.from_str(raw_val)
            scope = PolicyScope.from_str(raw_scope) or PolicyScope.PROCESS
            blocked = state.is_scope_blocked_by_gpo(scope)
            finding = PolicyFinding(
                technique=BypassTechnique.ENV_VAR,
                severity=PolicySeverity.HIGH if level.is_permissive() else PolicySeverity.LOW,
                target_level=level,
                target_scope=scope,
                description=f"[System.Environment]::SetEnvironmentVariable targeting PSExecutionPolicyPreference ({level.value})",
                statement_index=stmt_idx,
                line_number=line_num,
                matched_text=m2.group(0),
                requires_admin=scope.requires_elevation,
                blocked_by_gpo=blocked,
                mitigation="Enforce MachinePolicy via Active Directory GPO to defeat environment variable modifications.",
            )
            results.append((finding, level, scope))

        return results

    def _inspect_cmdlet_invocation(
        self, stmt_clean: str, stmt_raw: str, stmt_idx: int, line_num: int, state: ScopeState
    ) -> List[Tuple[PolicyFinding, ExecutionPolicyLevel, PolicyScope]]:
        results = []
        if not self._RE_SET_EP_CMDLET.search(stmt_clean):
            return results

        # Parse target policy level from parameters or positional token
        level = ExecutionPolicyLevel.UNDEFINED
        scope = PolicyScope.LOCAL_MACHINE  # Default scope for Set-ExecutionPolicy if omitted

        # Check named -ExecutionPolicy parameter
        ep_param = re.search(r"-(?:ExecutionPolicy|ep)\s+(['\"]?[A-Za-z]+['\"]?)", stmt_clean, re.IGNORECASE)
        if ep_param:
            level = ExecutionPolicyLevel.from_str(ep_param.group(1).strip("'\""))
        else:
            # Check positional argument after cmdlet
            tokens = stmt_clean.split()
            cmdlet_seen = False
            for token in tokens:
                clean_tok = token.strip("()',\"")
                if cmdlet_seen and not token.startswith("-"):
                    parsed_lvl = ExecutionPolicyLevel.from_str(clean_tok)
                    if parsed_lvl != ExecutionPolicyLevel.UNDEFINED:
                        level = parsed_lvl
                        break
                if any(c in token.lower() for c in ("set-executionpolicy", "set-ep")):
                    cmdlet_seen = True

        # Check named -Scope parameter
        scope_param = re.search(r"-(?:Scope|sc)\s+(['\"]?[A-Za-z]+['\"]?)", stmt_clean, re.IGNORECASE)
        if scope_param:
            parsed_scp = PolicyScope.from_str(scope_param.group(1).strip("'\""))
            if parsed_scp:
                scope = parsed_scp

        if level != ExecutionPolicyLevel.UNDEFINED:
            blocked = state.is_scope_blocked_by_gpo(scope)
            requires_admin = scope.requires_elevation
            severity = PolicySeverity.HIGH if level.is_permissive() else PolicySeverity.LOW
            if not requires_admin and level.is_permissive():
                # Setting Process or CurrentUser to Bypass requires zero admin rights
                severity = PolicySeverity.HIGH

            finding = PolicyFinding(
                technique=BypassTechnique.CMDLET_SET_POLICY,
                severity=severity,
                target_level=level,
                target_scope=scope,
                description=f"Invocation of Set-ExecutionPolicy targeting {level.value} on scope {scope.value}",
                statement_index=stmt_idx,
                line_number=line_num,
                matched_text=stmt_raw[:120],
                requires_admin=requires_admin,
                blocked_by_gpo=blocked,
                mitigation="Restrict execution policy modifications via Group Policy and enforce Constrained Language Mode.",
            )
            results.append((finding, level, scope))

        return results

    def _inspect_reflection_tampering(
        self, stmt_clean: str, stmt_raw: str, stmt_idx: int, line_num: int, state: ScopeState
    ) -> List[PolicyFinding]:
        results = []
        has_auth_type = bool(self._RE_AUTH_MGR_TYPE.search(stmt_clean))
        has_cached_ctx = bool(self._RE_CACHED_CONTEXT.search(stmt_clean))
        has_overwrite = bool(self._RE_AUTH_MGR_OVERWRITE.search(stmt_clean))

        if (has_auth_type and has_overwrite) or (has_cached_ctx and has_overwrite) or ("cachedContext" in stmt_clean and "AuthorizationManager" in stmt_clean):
            finding = PolicyFinding(
                technique=BypassTechnique.REFLECTION_AUTH_MGR,
                severity=PolicySeverity.CRITICAL,
                target_level=ExecutionPolicyLevel.BYPASS,
                target_scope=PolicyScope.PROCESS,
                description="In-memory .NET reflection tampering targeting AuthorizationManager / ExecutionContext (bypasses all policy and GPO enforcement)",
                statement_index=stmt_idx,
                line_number=line_num,
                matched_text=stmt_raw[:140],
                requires_admin=False,
                blocked_by_gpo=False,
                mitigation="Deploy ConstrainedLanguageMode (CLM) and AppLocker / WDAC to block .NET reflection into non-public runtime internals.",
            )
            results.append(finding)

        return results

    def _inspect_zone_identifier(
        self, stmt_clean: str, stmt_raw: str, stmt_idx: int, line_num: int
    ) -> List[PolicyFinding]:
        results = []
        if self._RE_UNBLOCK_FILE.search(stmt_clean) or self._RE_ZONE_ID_STRIP.search(stmt_clean):
            finding = PolicyFinding(
                technique=BypassTechnique.ADS_ZONE_STRIP,
                severity=PolicySeverity.HIGH,
                target_level=ExecutionPolicyLevel.UNRESTRICTED,
                target_scope=None,
                description="Stripping NTFS Zone.Identifier Alternate Data Stream (ADS) to bypass RemoteSigned policy on downloaded files",
                statement_index=stmt_idx,
                line_number=line_num,
                matched_text=stmt_raw[:120],
                requires_admin=False,
                blocked_by_gpo=False,
                mitigation="Configure AllSigned policy instead of RemoteSigned to mandate cryptographic signatures on all scripts.",
            )
            results.append(finding)
        return results

    def _inspect_registry_tampering(
        self, stmt_clean: str, stmt_raw: str, stmt_idx: int, line_num: int, state: ScopeState
    ) -> List[Tuple[PolicyFinding, ExecutionPolicyLevel, PolicyScope]]:
        results = []
        if self._RE_REG_EXEC_POLICY.search(stmt_clean):
            is_hklm = "hklm:" in stmt_clean.lower()
            scope = PolicyScope.LOCAL_MACHINE if is_hklm else PolicyScope.CURRENT_USER
            level = ExecutionPolicyLevel.BYPASS  # Default inferred if tampering with registry key directly
            if "unrestricted" in stmt_clean.lower():
                level = ExecutionPolicyLevel.UNRESTRICTED
            elif "remotesigned" in stmt_clean.lower():
                level = ExecutionPolicyLevel.REMOTE_SIGNED

            blocked = state.is_scope_blocked_by_gpo(scope)
            finding = PolicyFinding(
                technique=BypassTechnique.REGISTRY_TAMPERING,
                severity=PolicySeverity.HIGH,
                target_level=level,
                target_scope=scope,
                description=f"Direct registry manipulation targeting PowerShell ExecutionPolicy ({scope.value})",
                statement_index=stmt_idx,
                line_number=line_num,
                matched_text=stmt_raw[:120],
                requires_admin=scope.requires_elevation,
                blocked_by_gpo=blocked,
                mitigation="Audit registry modifications to ShellIds\\Microsoft.PowerShell and lock down permissions with GPO.",
            )
            results.append((finding, level, scope))
        return results

    def _inspect_embedded_cli(self, script_text: str, state: ScopeState) -> List[PolicyFinding]:
        findings = []
        lines = script_text.splitlines()
        for idx, line in enumerate(lines):
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue
            if "powershell" in line_clean.lower() or "pwsh" in line_clean.lower():
                cli_info = self.parse_cli_args(line_clean)
                for f in cli_info["findings"]:
                    f.line_number = idx + 1
                    findings.append(f)
        return findings

    def _apply_transition(
        self,
        state: ScopeState,
        scope: PolicyScope,
        level: ExecutionPolicyLevel,
        technique: BypassTechnique,
        stmt_raw: str,
        stmt_idx: int,
        forced: bool = False,
    ) -> PolicyTransition:
        prev_lvl, prev_scope = state.effective_policy()
        blocked = state.is_scope_blocked_by_gpo(scope) if not forced else False

        if not blocked:
            state.set_scope(scope, level)

        new_lvl, new_scope = state.effective_policy()
        effective_changed = new_lvl != prev_lvl

        desc = (
            f"Policy transition on {scope.value} to {level.value} (Effective: {new_lvl.value} via {new_scope})"
            if not blocked
            else f"Attempted policy change on {scope.value} to {level.value} BLOCKED by higher Group Policy ({new_scope})"
        )

        return PolicyTransition(
            step=stmt_idx,
            statement_snippet=stmt_raw[:80],
            technique=technique,
            previous_level=prev_lvl,
            previous_winning_scope=prev_scope,
            new_level=new_lvl,
            new_winning_scope=new_scope,
            effective_changed=effective_changed,
            blocked_by_gpo=blocked,
            description=desc,
        )

    def _calculate_risk_metrics(
        self,
        findings: List[PolicyFinding],
        initial_lvl: ExecutionPolicyLevel,
        final_lvl: ExecutionPolicyLevel,
    ) -> Tuple[int, str]:
        if not findings and not final_lvl.is_permissive():
            return 0, "CLEAN"

        score = 0
        has_critical = False
        for f in findings:
            if f.severity == PolicySeverity.CRITICAL:
                score += 50
                has_critical = True
            elif f.severity == PolicySeverity.HIGH:
                score += 25
            elif f.severity == PolicySeverity.MEDIUM:
                score += 15
            elif f.severity == PolicySeverity.LOW:
                score += 5

        # Boost score if final effective policy is permissive and initial was restrictive
        if initial_lvl in (ExecutionPolicyLevel.RESTRICTED, ExecutionPolicyLevel.ALL_SIGNED):
            if final_lvl == ExecutionPolicyLevel.BYPASS:
                score += 25
            elif final_lvl == ExecutionPolicyLevel.UNRESTRICTED:
                score += 15

        if has_critical:
            score = max(score, 75)

        score = min(score, 100)

        if score >= 75 or has_critical:
            return score, "CRITICAL"
        if score >= 50:
            return score, "HIGH"
        if score >= 25:
            return score, "MEDIUM"
        if score > 0:
            return score, "LOW"
        return 0, "CLEAN"

    def _generate_mitigations(self, findings: List[PolicyFinding], final_state: ScopeState) -> List[str]:
        mitigations = set()
        for f in findings:
            if f.mitigation:
                mitigations.add(f.mitigation)

        # Baseline security recommendations
        if final_state.machine_policy == ExecutionPolicyLevel.UNDEFINED:
            mitigations.add(
                "Enforce Computer Configuration -> Administrative Templates -> Windows Components -> Windows PowerShell -> 'Turn on Script Execution' (MachinePolicy) via Active Directory GPO."
            )
        mitigations.add("Deploy Windows Defender Application Control (WDAC) or AppLocker to enforce ConstrainedLanguageMode system-wide.")
        mitigations.add("Enable PowerShell ScriptBlock Logging (Event ID 4104) and Transcription Logging.")

        return sorted(list(mitigations))
