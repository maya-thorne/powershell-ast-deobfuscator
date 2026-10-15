"""
PowerShell Statement Span & Boundary Parser.
Splits script text into precise statement spans for static inspection and AST correlation.
Handles nested quotes, backtick escapes, braced variables, hashtable blocks, comments,
and compound control flow structures with zero semantic breakage.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .amsi_etw_signatures import AmsiEtwFinding


@dataclass
class SanitizationResult:
    """Forensic report resulting from bypass sanitization and neutralization."""
    sanitized_script: str
    findings: List[AmsiEtwFinding] = field(default_factory=list)
    neutralized_count: int = 0
    modifications: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "neutralized_count": self.neutralized_count,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "modifications": self.modifications,
            "sanitized_script": self.sanitized_script,
        }


def _strip_comments(text: str) -> str:
    """
    Strips single-line (#...) and block comments (<#...#>) from code,
    preserving all characters inside single and double quoted strings.
    """
    res: List[str] = []
    n = len(text)
    i = 0
    in_single = False
    in_double = False
    escape = False

    while i < n:
        ch = text[i]

        if escape:
            escape = False
            res.append(ch)
            i += 1
            continue

        if ch == "`" and not in_single:
            escape = True
            res.append(ch)
            i += 1
            continue

        if not in_single and not in_double:
            if ch == "<" and i + 1 < n and text[i + 1] == "#":
                i += 2
                while i < n:
                    if text[i] == "#" and i + 1 < n and text[i + 1] == ">":
                        i += 2
                        break
                    i += 1
                res.append(" ")
                continue
            if ch == "#":
                while i < n and text[i] not in ("\r", "\n"):
                    i += 1
                continue

        if ch == "'":
            if not in_double:
                if in_single and i + 1 < n and text[i + 1] == "'":
                    res.append("''")
                    i += 2
                    continue
                in_single = not in_single
        elif ch == '"':
            if not in_single:
                in_double = not in_double

        res.append(ch)
        i += 1

    return "".join(res)


_BYPASS_INDICATORS = (
    "amsiscanbuffer",
    "amsiscanstring",
    "amsiinitialize",
    "amsiopensession",
    "amsiinitfailed",
    "amsicontext",
    "etweventwrite",
    "etweventwritetransfer",
    "etweventwritestring",
    "etwprovider",
    "m_enabled",
    "cachedgrouppolicysettings",
    "wldpquerydynamiccodetrust",
    "wldpisclassinapprovedlist",
)

_CONTROL_KEYWORDS = (
    "if", "elseif", "else", "while", "for", "foreach",
    "try", "catch", "finally", "trap", "function", "filter",
    "class", "enum", "process", "begin", "end", "dynamicparam"
)


def _is_control_header(text: str) -> bool:
    t = text.strip().lower()
    for kw in _CONTROL_KEYWORDS:
        if t == kw or t.startswith(f"{kw} ") or t.startswith(f"{kw}(") or t.startswith(f"{kw}\t") or t.startswith(f"{kw}\n"):
            return True
    return False


def _has_bypass_indicator(text: str) -> bool:
    t = text.lower()
    return any(ind in t for ind in _BYPASS_INDICATORS)


def _has_continuation_clause(remaining: str) -> bool:
    clean = _strip_comments(remaining).lstrip()
    clean_lower = clean.lower()
    for clause in ("elseif", "else", "catch", "finally"):
        if (
            clean_lower == clause
            or clean_lower.startswith(f"{clause} ")
            or clean_lower.startswith(f"{clause}(")
            or clean_lower.startswith(f"{clause}\t")
            or clean_lower.startswith(f"{clause}\n")
            or clean_lower.startswith(f"{clause}{{")
        ):
            return True
    return False


def _get_statement_spans(text: str) -> List[Tuple[int, int]]:
    """
    Parses PowerShell script into (start_idx, end_idx) statement spans.
    Accurately handles single/double quotes, backticks, parentheses, brackets,
    scriptblock braces, single-line (#...) and block comments (<#...#>),
    hashtable literals (@{...}), braced variables (${...}), control flow
    structures (if/elseif/else, try/catch/finally), and statement separators (; and newlines).
    Pure comments and already-neutralized comment blocks are excluded from statement spans.
    """
    spans: List[Tuple[int, int]] = []
    n = len(text)
    stmt_start = 0
    depth_paren = 0
    depth_bracket = 0
    in_single = False
    in_double = False
    in_comment = False
    in_block_comment = False
    block_comment_start = 0
    escape = False
    brace_stack: List[Tuple[str, int]] = []
    control_stack: List[Tuple[int, bool]] = []

    def _emit_span(start: int, end: int) -> None:
        if end > start:
            chunk = text[start:end]
            stripped = chunk.strip()
            # Omit spans that are purely comments (single-line or block comments)
            if stripped and not stripped.startswith("#"):
                if not (stripped.startswith("<#") and stripped.endswith("#>")):
                    l_trim = len(chunk) - len(chunk.lstrip())
                    r_trim = len(chunk) - len(chunk.rstrip())
                    if start + l_trim < end - r_trim:
                        spans.append((start + l_trim, end - r_trim))

    i = 0
    while i < n:
        ch = text[i]

        if escape:
            escape = False
            i += 1
            continue

        if ch == "`" and not in_single and not in_comment and not in_block_comment:
            escape = True
            i += 1
            continue

        # Single-line comment handling
        if in_comment:
            if ch in ("\r", "\n"):
                in_comment = False
                if depth_paren == 0 and depth_bracket == 0 and not (brace_stack and brace_stack[-1][0] == "VAR"):
                    _emit_span(stmt_start, i)
                    stmt_start = i + 1
            i += 1
            continue

        # Block comment handling
        if in_block_comment:
            if ch == "#" and i + 1 < n and text[i + 1] == ">":
                in_block_comment = False
                i += 2
                # If everything between stmt_start and block_comment_start was whitespace,
                # advance stmt_start past this block comment so it's not part of a statement
                if not text[stmt_start:block_comment_start].strip():
                    stmt_start = i
                continue
            i += 1
            continue

        # Check for start of comments when outside quotes
        if not in_single and not in_double:
            if ch == "<" and i + 1 < n and text[i + 1] == "#":
                in_block_comment = True
                block_comment_start = i
                i += 2
                continue
            if ch == "#":
                in_comment = True
                i += 1
                continue

        # Single quotes
        if in_single:
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                in_single = False
            i += 1
            continue

        # Double quotes
        if in_double:
            if ch == '"':
                if i + 1 < n and text[i + 1] == '"':
                    i += 2
                    continue
                in_double = False
            i += 1
            continue

        # Outside quotes and comments
        if ch == "'":
            in_single = True
        elif ch == '"':
            in_double = True
        elif ch == "(":
            depth_paren += 1
        elif ch == ")":
            if depth_paren > 0:
                depth_paren -= 1
        elif ch == "[":
            depth_bracket += 1
        elif ch == "]":
            if depth_bracket > 0:
                depth_bracket -= 1
        elif ch == "{" and depth_paren == 0 and depth_bracket == 0:
            if i > 0 and text[i - 1] == "$":
                brace_stack.append(("VAR", i - 1))
            elif i > 0 and text[i - 1] == "@":
                brace_stack.append(("HASH", i - 1))
            else:
                brace_stack.append(("BLOCK", i))
                preceding = text[stmt_start:i]
                clean_prec = _strip_comments(preceding)
                is_ctrl = _is_control_header(clean_prec)
                has_byp = _has_bypass_indicator(clean_prec)
                ctrl_orig_start = stmt_start
                if control_stack and _has_continuation_clause(clean_prec):
                    prev_ctrl_start, prev_has_byp = control_stack.pop()
                    ctrl_orig_start = prev_ctrl_start
                    has_byp = has_byp or prev_has_byp

                control_stack.append((ctrl_orig_start, has_byp))
                if not is_ctrl and clean_prec.strip():
                    _emit_span(stmt_start, i)
                stmt_start = i + 1
        elif ch == "}" and depth_paren == 0 and depth_bracket == 0:
            if brace_stack:
                b_type, open_pos = brace_stack.pop()
                if b_type == "VAR":
                    # Braced variable ${...} does not split statement
                    pass
                elif b_type == "HASH":
                    # If entries were emitted inside hashtable, emit final entry
                    if stmt_start > open_pos:
                        _emit_span(stmt_start, i)
                        stmt_start = i + 1
                    # Else single-line hashtable: stmt_start is before @{, keep it intact
                elif b_type == "BLOCK":
                    _emit_span(stmt_start, i)
                    ctrl_start, had_bypass = control_stack.pop() if control_stack else (stmt_start, False)
                    rem = text[i + 1:]
                    has_cont = _has_continuation_clause(rem)
                    if has_cont:
                        control_stack.append((ctrl_start, had_bypass))
                        stmt_start = i + 1
                    elif had_bypass:
                        # Emit the entire compound control structure
                        _emit_span(ctrl_start, i + 1)
                        stmt_start = i + 1
                    else:
                        stmt_start = i + 1
            else:
                _emit_span(stmt_start, i)
                stmt_start = i + 1
        elif ch in (";", "\n", "\r") and depth_paren == 0 and depth_bracket == 0:
            if not (brace_stack and brace_stack[-1][0] == "VAR"):
                _emit_span(stmt_start, i)
                stmt_start = i + 1

        i += 1

    if stmt_start < n:
        _emit_span(stmt_start, n)

    return spans
