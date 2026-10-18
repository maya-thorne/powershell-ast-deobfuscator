"""
PowerShell ExecutionPolicy Reducer & Sanitization Engine.
Neutralizes execution policy bypass statements (comment, strip, or invert) and normalizes obfuscated invocations.
"""

from typing import Any, Dict, List, Optional, Tuple

from .policy_models import BypassTechnique, PolicyFinding
from .statement_span_parser import _get_statement_spans, _strip_comments


class PowerShellPolicyReducer:
    """
    Surgically sanitizes and neutralizes detected execution policy bypasses.
    Supports comment wrapping, statement stripping, and policy inversion modes.
    """

    def __init__(self, mode: str = "comment"):
        if mode not in ("comment", "strip", "invert"):
            raise ValueError(f"Invalid neutralization mode: {mode}. Must be 'comment', 'strip', or 'invert'.")
        self.mode = mode

    def neutralize(
        self, script_text: str, findings: List[PolicyFinding]
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Neutralizes execution policy bypass findings in the script.
        Returns the sanitized script text and a log of applied modifications.
        """
        if not findings:
            return script_text, []

        spans = _get_statement_spans(script_text)
        finding_stmt_indices = {f.statement_index: f for f in findings if f.statement_index > 0}
        modifications: List[Dict[str, Any]] = []

        # Process spans in reverse order to preserve string character offsets
        sorted_spans = sorted(enumerate(spans, 1), key=lambda x: x[1][0], reverse=True)
        result_chars = list(script_text)

        for stmt_idx, (start_idx, end_idx) in sorted_spans:
            if stmt_idx not in finding_stmt_indices:
                continue

            finding = finding_stmt_indices[stmt_idx]
            original_stmt = script_text[start_idx:end_idx]

            replacement = ""
            if self.mode == "comment":
                replacement = f"<# [NEUTRALIZED EXECUTION POLICY BYPASS: {finding.technique.value}] {original_stmt} #>"
            elif self.mode == "strip":
                replacement = ""
            elif self.mode == "invert":
                replacement = self._invert_statement(original_stmt, finding)

            result_chars[start_idx:end_idx] = list(replacement)

            modifications.append({
                "statement_index": stmt_idx,
                "technique": finding.technique.value,
                "original": original_stmt,
                "replacement": replacement,
                "mode": self.mode,
            })

        sanitized_script = "".join(result_chars)
        # Normalize double blank lines if stripped
        if self.mode == "strip":
            lines = [line for line in sanitized_script.splitlines() if line.strip()]
            sanitized_script = "\n".join(lines)

        return sanitized_script, modifications

    def _invert_statement(self, stmt: str, finding: PolicyFinding) -> str:
        """Inverts a permissive policy setting to Restricted or safe equivalent."""
        if finding.technique == BypassTechnique.ENV_VAR:
            return "$env:PSExecutionPolicyPreference = 'Restricted'"
        if finding.technique == BypassTechnique.CMDLET_SET_POLICY:
            scope = finding.target_scope.value if finding.target_scope else "Process"
            return f"Set-ExecutionPolicy Restricted -Scope {scope} -Force"
        if finding.technique == BypassTechnique.ADS_ZONE_STRIP:
            return "<# [NEUTRALIZED ZONE.IDENTIFIER STRIP] #>"
        if finding.technique == BypassTechnique.REFLECTION_AUTH_MGR:
            return "<# [NEUTRALIZED REFLECTION AUTHORIZATION MANAGER] #>"
        return f"<# [NEUTRALIZED POLICY BYPASS] {stmt} #>"
