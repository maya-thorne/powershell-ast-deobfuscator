"""
PowerShell AMSI & ETW Bypass Sanitizer & Neutralization Engine.
Safely neutralizes security impairment blocks (commenting, stripping, or inverting flags)
with span deduplication and right-to-left surgical substitution.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from .amsi_etw_signatures import AmsiEtwFinding
from .statement_span_parser import SanitizationResult


class AmsiEtwSanitizer:
    """
    Surgically sanitizes and neutralizes detected AMSI/ETW bypass blocks.
    Supports comment wrapping (<# [NEUTRALIZED: ...] #>), stripping, and boolean flag inversion.
    """

    @staticmethod
    def neutralize(
        script: str,
        findings: List[AmsiEtwFinding],
        mode: str = "comment",
    ) -> SanitizationResult:
        """
        Sanitizes and neutralizes all detected AMSI & ETW bypass blocks in the script.
        Supported modes:
          - 'comment': Wraps active bypass statements in <# [NEUTRALIZED: ...] ... #> (default)
          - 'strip': Removes bypass statements entirely while preserving adjacent benign code
          - 'invert': Safely inverts flag values (e.g., $true -> $false for amsiInitFailed)
        """
        if not findings:
            return SanitizationResult(
                sanitized_script=script,
                findings=[],
                neutralized_count=0,
                modifications=[],
            )

        # Build list of (start_pos, end_pos, finding)
        raw_spans: List[Tuple[int, int, AmsiEtwFinding]] = []
        for f in findings:
            if f.start_pos is not None and f.end_pos is not None and f.start_pos < f.end_pos:
                raw_spans.append((f.start_pos, f.end_pos, f))
            else:
                idx = script.find(f.matched_text)
                if idx != -1:
                    raw_spans.append((idx, idx + len(f.matched_text), f))

        # Sort raw spans by start_pos ascending
        raw_spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))

        # Resolve overlaps: eliminate spans that are inside another span or merge
        disjoint_spans: List[Tuple[int, int, AmsiEtwFinding]] = []
        for start, end, finding in raw_spans:
            if not disjoint_spans:
                disjoint_spans.append((start, end, finding))
                continue

            last_start, last_end, last_finding = disjoint_spans[-1]
            if start >= last_end:
                disjoint_spans.append((start, end, finding))
            elif start >= last_start and end <= last_end:
                # Contained completely inside previous span; already covered, skip
                continue
            else:
                # Partial overlap: merge to cover both
                new_start = min(last_start, start)
                new_end = max(last_end, end)
                disjoint_spans[-1] = (new_start, new_end, last_finding)

        # Apply replacements from RIGHT TO LEFT (descending start)
        disjoint_spans.sort(key=lambda s: s[0], reverse=True)

        sanitized = script
        modifications: List[Dict[str, Any]] = []

        for start, end, finding in disjoint_spans:
            target_str = script[start:end]

            if mode == "strip":
                replacement = ""
            elif mode == "invert" and finding.signature_id == "AMSI-REFL-001":
                replacement = re.sub(r"\$true\b", "$false", target_str, flags=re.IGNORECASE)
                replacement = re.sub(r",\s*1\s*\)", ", 0)", replacement)
                replacement = re.sub(r"=\s*1\b", "= 0", replacement)
                replacement = f"{replacement} <# [NEUTRALIZED: {finding.signature_id}] #>"
            elif mode == "invert" and finding.signature_id == "ETW-REFL-002":
                replacement = re.sub(r",\s*0\s*\)", ", 1)", target_str)
                replacement = re.sub(r",\s*\$false\s*\)", ", $true)", replacement, flags=re.IGNORECASE)
                replacement = re.sub(r"=\s*0\b", "= 1", replacement)
                replacement = re.sub(r"=\s*\$false\b", "= $true", replacement, flags=re.IGNORECASE)
                replacement = f"{replacement} <# [NEUTRALIZED: {finding.signature_id}] #>"
            else:
                safe_body = target_str.replace("#>", "# >").replace("<#", "< #")
                replacement = f"<# [NEUTRALIZED: {finding.signature_id}] {safe_body} #>"

            sanitized = sanitized[:start] + replacement + sanitized[end:]
            modifications.append({
                "signature_id": finding.signature_id,
                "target_symbol": finding.target_symbol,
                "original": target_str,
                "neutralized": replacement,
                "mode": mode,
                "start_pos": start,
                "end_pos": end,
            })

        return SanitizationResult(
            sanitized_script=sanitized,
            findings=findings,
            neutralized_count=len(modifications),
            modifications=modifications,
        )
