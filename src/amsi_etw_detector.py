"""
PowerShell AST AMSI & ETW Bypass Detection and Neutralization Engine.
Identifies in-memory patching (AmsiScanBuffer, EtwEventWrite) and reflection tampering
(amsiInitFailed, etwProvider, m_enabled, cachedGroupPolicySettings) with surgical
neutralization and sanitization capabilities.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .amsi_etw_signatures import (
    BUILTIN_SIGNATURES,
    DEFAULT_RULESET,
    AmsiEtwFinding,
    AmsiEtwRuleSet,
    BypassCategory,
    BypassSeverity,
    BypassSignature,
    TargetSystem,
)
from .ast_nodes import (
    ASTNode,
    ArrayLiteralNode,
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
    DynamicMemberAccessNode,
    DynamicMethodCallNode,
    DynamicStaticMemberAccessNode,
    ForEachStatementNode,
    FormatOpNode,
    ForStatementNode,
    IdentifierNode,
    IfStatementNode,
    IndexAccessNode,
    MemberAccessNode,
    MethodCallNode,
    NumberLiteralNode,
    ParenthesizedExpressionNode,
    PipelineNode,
    RangeExpressionNode,
    ScriptBlockNode,
    StaticMemberAccessNode,
    StringLiteralNode,
    SubexpressionNode,
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)


from .amsi_etw_sanitizer import AmsiEtwSanitizer
from .statement_span_parser import (
    SanitizationResult,
    _BYPASS_INDICATORS,
    _CONTROL_KEYWORDS,
    _get_statement_spans,
    _has_bypass_indicator,
    _has_continuation_clause,
    _is_control_header,
    _strip_comments,
)




class PowerShellAmsiEtwDetector:
    """
    Compiler-grade detector and sanitizer for AMSI & ETW bypass constructs.
    Inspects AST trees and normalized code for memory patching and reflection tampering.
    """

    def __init__(
        self,
        ruleset: Optional[AmsiEtwRuleSet] = None,
        symbols: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.ruleset = ruleset if ruleset is not None else DEFAULT_RULESET
        self.symbols = symbols if symbols is not None else {}

    # -------------------------------------------------------------------------
    # Detection Public API
    # -------------------------------------------------------------------------

    def detect(self, script: str) -> List[AmsiEtwFinding]:
        """
        Analyzes a PowerShell script string for AMSI and ETW bypass signatures.
        Returns a list of forensic findings ordered by line number and severity.
        """
        if not script or not script.strip():
            return []

        findings: List[AmsiEtwFinding] = []
        statement_spans = _get_statement_spans(script)
        claimed_spans: Set[Tuple[int, int]] = set()

        # 1. AMSI Memory Patches: AmsiScanBuffer (AMSI-MEM-001) & AmsiInitialize (AMSI-MEM-002)
        findings.extend(self._detect_amsi_mem_patches(script, statement_spans, claimed_spans))

        # 2. ETW Memory Patches: EtwEventWrite (ETW-MEM-001) & EtwEventWriteTransfer (ETW-MEM-002)
        findings.extend(self._detect_etw_mem_patches(script, statement_spans, claimed_spans))

        # 3. WLDP Code Trust Memory Patch (WLDP-MEM-001)
        findings.extend(self._detect_wldp_patch(script, statement_spans, claimed_spans))

        # 4. Reflection Tampering: amsiInitFailed (AMSI-REFL-001)
        findings.extend(self._detect_amsi_init_failed(script, statement_spans, claimed_spans))

        # 5. Reflection Tampering: amsiContext (AMSI-REFL-002)
        findings.extend(self._detect_amsi_context(script, statement_spans, claimed_spans))

        # 6. Reflection Tampering: PSEtwLogProvider.etwProvider (ETW-REFL-001)
        findings.extend(self._detect_etw_provider(script, statement_spans, claimed_spans))

        # 7. Reflection Tampering: EventProvider.m_enabled (ETW-REFL-002)
        findings.extend(self._detect_etw_m_enabled(script, statement_spans, claimed_spans))

        # 8. ScriptBlock Logging Suppression: cachedGroupPolicySettings (LOG-REFL-001)
        findings.extend(self._detect_cached_gp_settings(script, statement_spans, claimed_spans))

        # Deduplicate findings by (signature_id, start_pos, end_pos)
        unique_findings: List[AmsiEtwFinding] = []
        seen_keys: Set[Tuple[str, int, int]] = set()
        for f in findings:
            key = (f.signature_id, f.start_pos or 0, f.end_pos or 0)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        return sorted(unique_findings, key=lambda x: (x.line_number or 0, x.severity.value, x.start_pos or 0))

    def detect_ast(self, node: ASTNode) -> List[AmsiEtwFinding]:
        """Traverses parsed AST hierarchy and identifies bypass patterns."""
        try:
            from .normalizer import PowerShellNormalizer
            norm = PowerShellNormalizer(symbols=self.symbols)
            norm_node = norm.normalize(node)
            src = norm.to_source(norm_node)
            if src and src.strip():
                findings = self.detect(src)
                if findings:
                    return findings
        except Exception:
            pass

        extracted_strings = self._collect_strings_from_ast(node)
        merged = " ".join(extracted_strings)
        return self.detect(merged)

    def has_bypass(self, script: str) -> bool:
        """Returns True if any AMSI/ETW/Logging bypass pattern is detected."""
        return len(self.detect(script)) > 0

    def has_amsi_bypass(self, script: str) -> bool:
        """Returns True if an AMSI bypass pattern is detected."""
        return any(f.target_system == TargetSystem.AMSI for f in self.detect(script))

    def has_etw_bypass(self, script: str) -> bool:
        """Returns True if an ETW bypass pattern is detected."""
        return any(f.target_system == TargetSystem.ETW for f in self.detect(script))

    # -------------------------------------------------------------------------
    # Neutralization / Sanitization Public API
    # -------------------------------------------------------------------------

    def neutralize(self, script: str, mode: str = "comment") -> SanitizationResult:
        """
        Sanitizes and neutralizes all detected AMSI & ETW bypass blocks in the script.
        Supported modes:
          - 'comment': Wraps active bypass statements in <# [NEUTRALIZED: ...] ... #> (default)
          - 'strip': Removes bypass statements entirely while preserving adjacent benign code
          - 'invert': Safely inverts flag values (e.g., $true -> $false for amsiInitFailed)
        """
        findings = self.detect(script)
        return AmsiEtwSanitizer.neutralize(script, findings, mode=mode)

    def sanitize(self, script: str, mode: str = "comment") -> SanitizationResult:
        """Alias for neutralize()."""
        return self.neutralize(script, mode=mode)

    # -------------------------------------------------------------------------
    # Internal Pattern Detectors
    # -------------------------------------------------------------------------

    def _find_line_number(self, text: str, pos: int) -> int:
        return text[:pos].count("\n") + 1

    def _detect_amsi_mem_patches(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
    ) -> List[AmsiEtwFinding]:
        findings: List[AmsiEtwFinding] = []

        for idx, (st, end) in enumerate(spans):
            if (st, end) in claimed_spans:
                continue

            stmt = script[st:end]
            clean = _strip_comments(stmt)
            lower = clean.lower()

            is_scan_buffer = "amsiscanbuffer" in lower or "amsiscanstring" in lower
            is_amsi_init = "amsiinitialize" in lower or "amsiopensession" in lower

            if is_scan_buffer or is_amsi_init:
                # Filter out pure logging/informational cmdlets without API or assignment calls
                if re.match(r"^\s*write-(host|output|verbose|debug|warning|information)\b", lower):
                    if not any(k in lower for k in ["getprocaddress", "virtualprotect", "marshal", "loadlibrary", "="]):
                        continue

                sig_id = "AMSI-MEM-001" if is_scan_buffer else "AMSI-MEM-002"
                sig_name = "AmsiScanBuffer Memory Patching" if is_scan_buffer else "AmsiInitialize / AmsiOpenSession Memory Patching"
                sym = "AmsiScanBuffer" if is_scan_buffer else ("AmsiInitialize" if "amsiinitialize" in lower else "AmsiOpenSession")
                desc = (
                    "Detected in-memory patching of amsi.dll!AmsiScanBuffer via memory protection modification and byte overwriting."
                    if is_scan_buffer
                    else "Detected in-memory patching of amsi.dll!AmsiInitialize or AmsiOpenSession."
                )

                line = self._find_line_number(script, st)
                findings.append(AmsiEtwFinding(
                    signature_id=sig_id,
                    signature_name=sig_name,
                    category=BypassCategory.MEMORY_PATCH,
                    target_system=TargetSystem.AMSI,
                    severity=BypassSeverity.CRITICAL,
                    mitre_id="T1562.001",
                    confidence=1.0,
                    matched_text=stmt,
                    description=desc,
                    line_number=line,
                    target_symbol=sym,
                    start_pos=st,
                    end_pos=end,
                ))
                claimed_spans.add((st, end))

                # Track assigned variable and claim related write statements
                m_var = re.search(r"\$([a-zA-Z0-9_]+)\s*=", stmt)
                target_var = m_var.group(1).lower() if m_var else None

                self._claim_related_write_statements(
                    script, spans, claimed_spans, idx, target_var, sig_id, sig_name, sym, findings
                )

        return findings

    def _detect_etw_mem_patches(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
    ) -> List[AmsiEtwFinding]:
        findings: List[AmsiEtwFinding] = []

        for idx, (st, end) in enumerate(spans):
            if (st, end) in claimed_spans:
                continue

            stmt = script[st:end]
            clean = _strip_comments(stmt)
            lower = clean.lower()

            is_transfer = "etweventwritetransfer" in lower or "etweventwritestring" in lower
            is_etw_write = ("etweventwrite" in lower) and not is_transfer

            if is_transfer or is_etw_write:
                # Filter out pure logging/informational cmdlets without API or assignment calls
                if re.match(r"^\s*write-(host|output|verbose|debug|warning|information)\b", lower):
                    if not any(k in lower for k in ["getprocaddress", "virtualprotect", "marshal", "loadlibrary", "="]):
                        continue

                sig_id = "ETW-MEM-002" if is_transfer else "ETW-MEM-001"
                sig_name = (
                    "EtwEventWriteTransfer / EtwEventWriteString Memory Patching"
                    if is_transfer
                    else "EtwEventWrite Memory Patching"
                )
                sym = (
                    ("EtwEventWriteTransfer" if "etweventwritetransfer" in lower else "EtwEventWriteString")
                    if is_transfer
                    else "EtwEventWrite"
                )
                desc = (
                    "Detected in-memory patching of ntdll.dll!EtwEventWriteTransfer or EtwEventWriteString to prevent event delivery."
                    if is_transfer
                    else "Detected memory patching of ntdll.dll!EtwEventWrite blinding Event Tracing for Windows and ScriptBlock Logging."
                )

                line = self._find_line_number(script, st)
                findings.append(AmsiEtwFinding(
                    signature_id=sig_id,
                    signature_name=sig_name,
                    category=BypassCategory.MEMORY_PATCH,
                    target_system=TargetSystem.ETW,
                    severity=BypassSeverity.CRITICAL,
                    mitre_id="T1562.001",
                    confidence=1.0,
                    matched_text=stmt,
                    description=desc,
                    line_number=line,
                    target_symbol=sym,
                    start_pos=st,
                    end_pos=end,
                ))
                claimed_spans.add((st, end))

                # Track assigned variable and claim related write statements
                m_var = re.search(r"\$([a-zA-Z0-9_]+)\s*=", stmt)
                target_var = m_var.group(1).lower() if m_var else None

                self._claim_related_write_statements(
                    script, spans, claimed_spans, idx, target_var, sig_id, sig_name, sym, findings
                )

        return findings

    def _claim_related_write_statements(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
        current_idx: int,
        target_var: Optional[str],
        sig_id: str,
        sig_name: str,
        sym: str,
        findings: List[AmsiEtwFinding],
    ) -> None:
        """Finds and attaches subsequent memory write and protect statements to the patch finding."""
        for j in range(current_idx + 1, min(current_idx + 8, len(spans))):
            sub_st, sub_end = spans[j]
            if (sub_st, sub_end) in claimed_spans:
                continue

            sub_stmt = script[sub_st:sub_end]
            sub_lower = _strip_comments(sub_stmt).lower()

            is_write_api = (
                "marshal]::copy" in sub_lower
                or "writeprocessmemory" in sub_lower
                or "marshal]::write" in sub_lower
                or "ntwritevirtualmemory" in sub_lower
            )
            is_protect_api = "virtualprotect" in sub_lower

            matches_var = (target_var is not None and f"${target_var}" in sub_lower)
            if (is_write_api or is_protect_api) and (matches_var or target_var is None):
                claimed_spans.add((sub_st, sub_end))
                line = self._find_line_number(script, sub_st)
                findings.append(AmsiEtwFinding(
                    signature_id=sig_id,
                    signature_name=sig_name,
                    category=BypassCategory.MEMORY_PATCH,
                    target_system=TargetSystem.AMSI if sig_id.startswith("AMSI") else TargetSystem.ETW,
                    severity=BypassSeverity.CRITICAL,
                    mitre_id="T1562.001",
                    confidence=1.0,
                    matched_text=sub_stmt,
                    description=f"Detected memory patch payload write targeting {sym}.",
                    line_number=line,
                    target_symbol=sym,
                    start_pos=sub_st,
                    end_pos=sub_end,
                ))
                if is_write_api and target_var is None:
                    break

    def _claim_related_reflection_execution(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
        current_idx: int,
        target_var: Optional[str],
        sig_id: str,
        sig_name: str,
        category: BypassCategory,
        target_sys: TargetSystem,
        severity: BypassSeverity,
        sym: str,
        findings: List[AmsiEtwFinding],
    ) -> None:
        """Finds and attaches subsequent reflection execution/setter statements (e.g., .SetValue, .GetValue, ['...']=)."""
        if not target_var:
            return
        tracked_vars = {target_var}
        for j in range(current_idx + 1, min(current_idx + 8, len(spans))):
            sub_st, sub_end = spans[j]
            if (sub_st, sub_end) in claimed_spans:
                continue

            sub_stmt = script[sub_st:sub_end]
            sub_lower = _strip_comments(sub_stmt).lower()

            is_receiver = any(
                re.search(rf"\${re.escape(v)}\s*\.\s*(setvalue|getvalue)", sub_lower)
                or f"${v}[" in sub_lower
                for v in tracked_vars
            )
            if not is_receiver:
                continue

            # Track variable propagation like $dict = $field.GetValue($null)
            m_assign = re.search(r"\$([a-zA-Z0-9_]+)\s*=", sub_stmt)
            if m_assign:
                tracked_vars.add(m_assign.group(1).lower())

            claimed_spans.add((sub_st, sub_end))
            line = self._find_line_number(script, sub_st)
            findings.append(AmsiEtwFinding(
                signature_id=sig_id,
                signature_name=sig_name,
                category=category,
                target_system=target_sys,
                severity=severity,
                mitre_id="T1562.001",
                confidence=1.0,
                matched_text=sub_stmt,
                description=f"Detected reflection tampering execution targeting {sym}.",
                line_number=line,
                target_symbol=sym,
                start_pos=sub_st,
                end_pos=sub_end,
            ))

    def _detect_wldp_patch(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
    ) -> List[AmsiEtwFinding]:
        findings: List[AmsiEtwFinding] = []
        for idx, (st, end) in enumerate(spans):
            if (st, end) in claimed_spans:
                continue

            stmt = script[st:end]
            clean = _strip_comments(stmt)
            lower = clean.lower()
            if "wldpquerydynamiccodetrust" in lower or "wldpisclassinapprovedlist" in lower:
                # Filter out pure logging
                if re.match(r"^\s*write-(host|output|verbose|debug|warning|information)\b", lower):
                    if not any(k in lower for k in ["getprocaddress", "virtualprotect", "marshal", "loadlibrary", "="]):
                        continue

                sym = "WldpQueryDynamicCodeTrust" if "wldpquerydynamiccodetrust" in lower else "WldpIsClassInApprovedList"
                line = self._find_line_number(script, st)
                findings.append(AmsiEtwFinding(
                    signature_id="WLDP-MEM-001",
                    signature_name="WLDP QueryDynamicCodeTrust Memory Patching",
                    category=BypassCategory.MEMORY_PATCH,
                    target_system=TargetSystem.WLDP,
                    severity=BypassSeverity.HIGH,
                    mitre_id="T1562.001",
                    confidence=0.9,
                    matched_text=stmt,
                    description="Detected in-memory patching of WLDP code trust verification routines.",
                    line_number=line,
                    target_symbol=sym,
                    start_pos=st,
                    end_pos=end,
                ))
                claimed_spans.add((st, end))
        return findings

    def _detect_amsi_init_failed(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
    ) -> List[AmsiEtwFinding]:
        findings: List[AmsiEtwFinding] = []
        for idx, (st, end) in enumerate(spans):
            if (st, end) in claimed_spans:
                continue

            stmt = script[st:end]
            clean = _strip_comments(stmt)
            lower = clean.lower()
            if "amsiinitfailed" in lower:
                # Filter out pure logging
                if re.match(r"^\s*write-(host|output|verbose|debug|warning|information)\b", lower):
                    if not any(k in lower for k in ["getfield", "setvalue", "="]):
                        continue

                line = self._find_line_number(script, st)
                findings.append(AmsiEtwFinding(
                    signature_id="AMSI-REFL-001",
                    signature_name="amsiInitFailed Reflection Tampering",
                    category=BypassCategory.REFLECTION_TAMPERING,
                    target_system=TargetSystem.AMSI,
                    severity=BypassSeverity.CRITICAL,
                    mitre_id="T1562.001",
                    confidence=1.0,
                    matched_text=stmt,
                    description="Detected reflection tampering forcing AmsiUtils.amsiInitFailed to true to bypass AMSI scanning.",
                    line_number=line,
                    target_symbol="amsiInitFailed",
                    start_pos=st,
                    end_pos=end,
                ))
                claimed_spans.add((st, end))

                # Track assigned variable and claim subsequent SetValue statements across intermediate lines
                m_var = re.search(r"\$([a-zA-Z0-9_]+)\s*=", stmt)
                target_var = m_var.group(1).lower() if m_var else None
                self._claim_related_reflection_execution(
                    script, spans, claimed_spans, idx, target_var,
                    "AMSI-REFL-001", "amsiInitFailed Reflection Tampering",
                    BypassCategory.REFLECTION_TAMPERING, TargetSystem.AMSI,
                    BypassSeverity.CRITICAL, "amsiInitFailed", findings
                )

        return findings

    def _detect_amsi_context(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
    ) -> List[AmsiEtwFinding]:
        findings: List[AmsiEtwFinding] = []
        for idx, (st, end) in enumerate(spans):
            if (st, end) in claimed_spans:
                continue

            stmt = script[st:end]
            clean = _strip_comments(stmt)
            lower = clean.lower()
            if "amsicontext" in lower:
                if re.match(r"^\s*write-(host|output|verbose|debug|warning|information)\b", lower):
                    if not any(k in lower for k in ["getfield", "setvalue", "="]):
                        continue

                line = self._find_line_number(script, st)
                findings.append(AmsiEtwFinding(
                    signature_id="AMSI-REFL-002",
                    signature_name="amsiContext Reflection Corruption",
                    category=BypassCategory.CONTEXT_CORRUPTION,
                    target_system=TargetSystem.AMSI,
                    severity=BypassSeverity.HIGH,
                    mitre_id="T1562.001",
                    confidence=0.92,
                    matched_text=stmt,
                    description="Detected tampering or memory corruption targeting AmsiUtils.amsiContext handle.",
                    line_number=line,
                    target_symbol="amsiContext",
                    start_pos=st,
                    end_pos=end,
                ))
                claimed_spans.add((st, end))

                m_var = re.search(r"\$([a-zA-Z0-9_]+)\s*=", stmt)
                target_var = m_var.group(1).lower() if m_var else None
                self._claim_related_reflection_execution(
                    script, spans, claimed_spans, idx, target_var,
                    "AMSI-REFL-002", "amsiContext Reflection Corruption",
                    BypassCategory.CONTEXT_CORRUPTION, TargetSystem.AMSI,
                    BypassSeverity.HIGH, "amsiContext", findings
                )

        return findings

    def _detect_etw_provider(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
    ) -> List[AmsiEtwFinding]:
        findings: List[AmsiEtwFinding] = []
        for idx, (st, end) in enumerate(spans):
            if (st, end) in claimed_spans:
                continue

            stmt = script[st:end]
            clean = _strip_comments(stmt)
            lower = clean.lower()
            if "etwprovider" in lower:
                if re.match(r"^\s*write-(host|output|verbose|debug|warning|information)\b", lower):
                    if not any(k in lower for k in ["getfield", "setvalue", "="]):
                        continue

                line = self._find_line_number(script, st)
                findings.append(AmsiEtwFinding(
                    signature_id="ETW-REFL-001",
                    signature_name="PSEtwLogProvider.etwProvider Reflection Tampering",
                    category=BypassCategory.REFLECTION_TAMPERING,
                    target_system=TargetSystem.ETW,
                    severity=BypassSeverity.HIGH,
                    mitre_id="T1562.001",
                    confidence=0.92,
                    matched_text=stmt,
                    description="Detected reflection tampering nullifying PSEtwLogProvider.etwProvider to suppress event emission.",
                    line_number=line,
                    target_symbol="etwProvider",
                    start_pos=st,
                    end_pos=end,
                ))
                claimed_spans.add((st, end))

                m_var = re.search(r"\$([a-zA-Z0-9_]+)\s*=", stmt)
                target_var = m_var.group(1).lower() if m_var else None
                self._claim_related_reflection_execution(
                    script, spans, claimed_spans, idx, target_var,
                    "ETW-REFL-001", "PSEtwLogProvider.etwProvider Reflection Tampering",
                    BypassCategory.REFLECTION_TAMPERING, TargetSystem.ETW,
                    BypassSeverity.HIGH, "etwProvider", findings
                )

        return findings

    def _detect_etw_m_enabled(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
    ) -> List[AmsiEtwFinding]:
        findings: List[AmsiEtwFinding] = []
        for idx, (st, end) in enumerate(spans):
            if (st, end) in claimed_spans:
                continue

            stmt = script[st:end]
            clean = _strip_comments(stmt)
            lower = clean.lower()
            if "m_enabled" in lower:
                # Require association with EventProvider / reflection / logging suppression
                is_refl = any(ind in lower for ind in ["eventprovider", "eventing", "psetwlogprovider", "etwprovider", "getfield", "nonpublic", "bindingflags", "reflection"])
                is_script_refl = any(ind in script.lower() for ind in ["eventprovider", "eventing", "psetwlogprovider", "etwprovider"])
                if not (is_refl or is_script_refl):
                    continue

                if re.match(r"^\s*write-(host|output|verbose|debug|warning|information)\b", lower):
                    if not any(k in lower for k in ["getfield", "setvalue", "="]):
                        continue

                line = self._find_line_number(script, st)
                findings.append(AmsiEtwFinding(
                    signature_id="ETW-REFL-002",
                    signature_name="EventProvider.m_enabled Reflection Tampering",
                    category=BypassCategory.REFLECTION_TAMPERING,
                    target_system=TargetSystem.ETW,
                    severity=BypassSeverity.HIGH,
                    mitre_id="T1562.001",
                    confidence=0.94,
                    matched_text=stmt,
                    description="Detected tampering with private field EventProvider.m_enabled silencing ETW logging.",
                    line_number=line,
                    target_symbol="m_enabled",
                    start_pos=st,
                    end_pos=end,
                ))
                claimed_spans.add((st, end))

                m_var = re.search(r"\$([a-zA-Z0-9_]+)\s*=", stmt)
                target_var = m_var.group(1).lower() if m_var else None
                self._claim_related_reflection_execution(
                    script, spans, claimed_spans, idx, target_var,
                    "ETW-REFL-002", "EventProvider.m_enabled Reflection Tampering",
                    BypassCategory.REFLECTION_TAMPERING, TargetSystem.ETW,
                    BypassSeverity.HIGH, "m_enabled", findings
                )

        return findings

    def _detect_cached_gp_settings(
        self,
        script: str,
        spans: List[Tuple[int, int]],
        claimed_spans: Set[Tuple[int, int]],
    ) -> List[AmsiEtwFinding]:
        findings: List[AmsiEtwFinding] = []
        for idx, (st, end) in enumerate(spans):
            if (st, end) in claimed_spans:
                continue

            stmt = script[st:end]
            clean = _strip_comments(stmt)
            lower = clean.lower()
            if "cachedgrouppolicysettings" in lower:
                if re.match(r"^\s*write-(host|output|verbose|debug|warning|information)\b", lower):
                    if not any(k in lower for k in ["getfield", "setvalue", "="]):
                        continue

                line = self._find_line_number(script, st)
                findings.append(AmsiEtwFinding(
                    signature_id="LOG-REFL-001",
                    signature_name="cachedGroupPolicySettings Reflection Tampering",
                    category=BypassCategory.LOGGING_SUPPRESSION,
                    target_system=TargetSystem.SCRIPT_LOGGING,
                    severity=BypassSeverity.HIGH,
                    mitre_id="T1562.001",
                    confidence=0.96,
                    matched_text=stmt,
                    description="Detected reflection tampering with cachedGroupPolicySettings dictionary disabling ScriptBlock Logging.",
                    line_number=line,
                    target_symbol="cachedGroupPolicySettings",
                    start_pos=st,
                    end_pos=end,
                ))
                claimed_spans.add((st, end))

                m_var = re.search(r"\$([a-zA-Z0-9_]+)\s*=", stmt)
                target_var = m_var.group(1).lower() if m_var else None
                self._claim_related_reflection_execution(
                    script, spans, claimed_spans, idx, target_var,
                    "LOG-REFL-001", "cachedGroupPolicySettings Reflection Tampering",
                    BypassCategory.LOGGING_SUPPRESSION, TargetSystem.SCRIPT_LOGGING,
                    BypassSeverity.HIGH, "cachedGroupPolicySettings", findings
                )

        return findings

    # -------------------------------------------------------------------------
    # Helper Utilities
    # -------------------------------------------------------------------------

    def _collect_strings_from_ast(self, node: ASTNode) -> List[str]:
        """Extracts string and identifier literals across an AST tree."""
        results: List[str] = []

        def _walk(n: Any) -> None:
            if n is None:
                return
            if isinstance(n, StringLiteralNode):
                results.append(n.value)
            elif isinstance(n, VariableNode):
                results.append(n.name)
            elif isinstance(n, IdentifierNode):
                results.append(n.name)
            elif isinstance(n, NumberLiteralNode):
                results.append(str(n.value))
            elif isinstance(n, CommandNode):
                _walk(n.target)
                for arg in n.arguments:
                    _walk(arg)
            elif isinstance(n, PipelineNode):
                for el in n.elements:
                    _walk(el)
            elif isinstance(n, MemberAccessNode):
                results.append(n.member)
                _walk(n.target)
            elif isinstance(n, StaticMemberAccessNode):
                results.append(n.type_name)
                results.append(n.member)
                if n.arguments:
                    for arg in n.arguments:
                        _walk(arg)
            elif isinstance(n, DynamicMemberAccessNode):
                _walk(n.target)
                _walk(n.member_expr)
            elif isinstance(n, DynamicStaticMemberAccessNode):
                results.append(n.type_name)
                _walk(n.member_expr)
                if n.arguments:
                    for arg in n.arguments:
                        _walk(arg)
            elif isinstance(n, MethodCallNode):
                results.append(n.method_name)
                _walk(n.target)
                for arg in n.arguments:
                    _walk(arg)
            elif isinstance(n, DynamicMethodCallNode):
                _walk(n.target)
                _walk(n.member_expr)
                for arg in n.arguments:
                    _walk(arg)
            elif isinstance(n, TypeCastNode):
                results.append(n.type_name)
                _walk(n.expression)
            elif isinstance(n, IndexAccessNode):
                _walk(n.target)
                _walk(n.index)
            elif isinstance(n, BinaryOpNode):
                _walk(n.left)
                _walk(n.right)
            elif isinstance(n, UnaryOpNode):
                _walk(n.operand)
            elif isinstance(n, AssignmentNode):
                _walk(n.variable)
                _walk(n.expression)
            elif isinstance(n, ScriptBlockNode):
                for s in n.statements:
                    _walk(s)
            elif isinstance(n, SubexpressionNode):
                for s in n.statements:
                    _walk(s)
            elif isinstance(n, ArrayLiteralNode):
                for el in n.elements:
                    _walk(el)
            elif isinstance(n, FormatOpNode):
                _walk(n.format_string)
                for arg in n.arguments:
                    _walk(arg)
            elif isinstance(n, ParenthesizedExpressionNode):
                _walk(n.expression)
            elif isinstance(n, RangeExpressionNode):
                _walk(n.start)
                _walk(n.end)
            elif isinstance(n, IfStatementNode):
                _walk(n.condition)
                _walk(n.then_branch)
                _walk(n.else_branch)
            elif isinstance(n, WhileStatementNode):
                _walk(n.condition)
                _walk(n.body)
            elif isinstance(n, ForStatementNode):
                _walk(n.initializer)
                _walk(n.condition)
                _walk(n.iterator)
                _walk(n.body)
            elif isinstance(n, ForEachStatementNode):
                _walk(n.variable)
                _walk(n.collection)
                _walk(n.body)

        _walk(node)
        return results


def detect_amsi_etw(script: str) -> List[AmsiEtwFinding]:
    """Convenience functional interface to detect AMSI/ETW bypass patterns."""
    return PowerShellAmsiEtwDetector().detect(script)


def neutralize_amsi_etw(script: str, mode: str = "comment") -> SanitizationResult:
    """Convenience functional interface to neutralize AMSI/ETW bypass patterns."""
    return PowerShellAmsiEtwDetector().neutralize(script, mode=mode)
