"""
PowerShell Deobfuscation Benchmark Metrics & Fidelity Measurement Engine.
Calculates Shannon entropy, size reduction, evasion artifact frequencies,
indicator recovery recall, AST syntax validity, and composite fidelity score.
"""

from collections import Counter
from dataclasses import dataclass, field
import math
import re
from typing import Any, Dict, List, Optional, Tuple

from .ast_nodes import ASTNode
from .lexer import PowerShellLexer
from .parser import PowerShellParser


@dataclass
class SampleBenchmarkResult:
    """
    Detailed benchmark execution evaluation metrics for a single corpus sample.
    """
    sample_id: str
    name: str
    category: str
    original_script: str
    deobfuscated_script: str
    original_entropy: float
    deobfuscated_entropy: float
    entropy_reduction: float
    original_length: int
    deobfuscated_length: int
    size_reduction_pct: float
    original_artifacts: Dict[str, int]
    deobfuscated_artifacts: Dict[str, int]
    artifacts_removed: int
    expected_indicators: List[str]
    recovered_indicators: List[str]
    missing_indicators: List[str]
    indicator_recall: float
    ast_valid: bool
    ast_node_count: int
    fidelity_score: float
    execution_time_ms: float
    success: bool
    error_message: Optional[str] = None


@dataclass
class CorpusBenchmarkSummary:
    """
    Aggregate summary telemetry across the complete corpus or category subset.
    """
    total_samples: int
    successful_samples: int
    failed_samples: int
    average_fidelity_score: float
    average_indicator_recall: float
    average_entropy_reduction: float
    average_size_reduction_pct: float
    ast_validity_rate: float
    total_execution_time_ms: float
    results: List[SampleBenchmarkResult] = field(default_factory=list)
    category_summaries: Dict[str, Dict[str, float]] = field(default_factory=dict)


def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon entropy (in bits per character) of a text string.
    """
    if not text:
        return 0.0
    total = len(text)
    counts = Counter(text)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return round(entropy, 4)


def calculate_size_reduction(original: str, deobfuscated: str) -> float:
    """
    Calculates percentage size reduction between original and deobfuscated script.
    Positive values indicate size reduction; negative values indicate expansion.
    """
    orig_len = len(original)
    deob_len = len(deobfuscated)
    if orig_len == 0:
        return 0.0
    pct = ((orig_len - deob_len) / orig_len) * 100.0
    return round(pct, 2)


def detect_artifacts(script: str) -> Dict[str, int]:
    """
    Detects and counts frequencies of common PowerShell obfuscation artifacts:
    - Backtick evasion symbols
    - Format operator invocation (-f / -format)
    - Base64 command flags (-e, -enc, -EncodedCommand)
    - Shuffled index access slices ([1,3,0], [13..0])
    - Nested subexpression prefixes ($()
    - Casing anomalies (erratic mixed-case identifiers)
    """
    if not script:
        return {
            "backticks": 0,
            "format_operators": 0,
            "base64_flags": 0,
            "shuffled_indices": 0,
            "nested_subexpressions": 0,
            "casing_anomalies": 0,
            "total": 0,
        }

    backticks = script.count("`")
    format_operators = len(re.findall(r"-(?:f|format)\b", script, re.IGNORECASE))
    base64_flags = len(re.findall(r"-(?:e|enc|encodedcommand)\b", script, re.IGNORECASE))
    shuffled_indices = len(re.findall(r"\[\s*-?\d+\s*(?:\.\.\s*-?\d+|,\s*-?\d+)*\s*\]", script))
    nested_subexpressions = script.count("$(")

    # Casing anomalies: identifiers with mixed alternating casing (e.g., InVoKe, sAPs)
    words = re.findall(r"\b[A-Za-z0-9_-]+\b", script)
    casing_anomalies = 0
    for word in words:
        clean = word.replace("-", "").replace("_", "")
        if len(clean) >= 4 and not clean.isupper() and not clean.islower() and not clean.istitle():
            # Check for multiple uppercase transitions
            upper_runs = len(re.findall(r"[A-Z]+", clean))
            lower_runs = len(re.findall(r"[a-z]+", clean))
            if upper_runs >= 2 and lower_runs >= 2:
                casing_anomalies += 1

    total = (
        backticks
        + format_operators
        + base64_flags
        + shuffled_indices
        + nested_subexpressions
        + casing_anomalies
    )

    return {
        "backticks": backticks,
        "format_operators": format_operators,
        "base64_flags": base64_flags,
        "shuffled_indices": shuffled_indices,
        "nested_subexpressions": nested_subexpressions,
        "casing_anomalies": casing_anomalies,
        "total": total,
    }


def calculate_indicator_recall(
    expected_indicators: List[str],
    deobfuscated_script: str
) -> Tuple[float, List[str], List[str]]:
    """
    Measures indicator recovery recall against expected ground-truth strings.
    Returns (recall_ratio, recovered_indicators, missing_indicators).
    """
    if not expected_indicators:
        return 1.0, [], []

    recovered: List[str] = []
    missing: List[str] = []

    for indicator in expected_indicators:
        if indicator in deobfuscated_script:
            recovered.append(indicator)
        else:
            missing.append(indicator)

    recall = len(recovered) / len(expected_indicators)
    return round(recall, 4), recovered, missing


def _count_ast_nodes(node: ASTNode) -> int:
    """Recursively counts AST nodes in parsed syntax tree."""
    count = 1
    for attr in dir(node):
        if attr.startswith("_"):
            continue
        try:
            val = getattr(node, attr)
            if isinstance(val, ASTNode):
                count += _count_ast_nodes(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, ASTNode):
                        count += _count_ast_nodes(item)
        except Exception:
            pass
    return count


def check_ast_validity(script: str) -> Tuple[bool, int, Optional[str]]:
    """
    Verifies that the script conforms to standard PowerShell syntax by parsing
    it into an AST with PowerShellLexer and PowerShellParser.
    Returns (is_valid, node_count, error_message).
    """
    if not script.strip():
        return False, 0, "Empty script content"

    try:
        lexer = PowerShellLexer(script)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        ast = parser.parse()
        node_count = _count_ast_nodes(ast)
        return True, node_count, None
    except Exception as ex:
        return False, 0, str(ex)


def calculate_fidelity_score(
    recall: float,
    ast_valid: bool,
    orig_artifacts: Dict[str, int],
    deob_artifacts: Dict[str, int],
    orig_entropy: float,
    deob_entropy: float,
) -> float:
    """
    Computes composite deobfuscation fidelity score (0.0 to 100.0%):
    - Ground-truth Indicator Recall: 45% weight
    - AST Syntax Validity: 25% weight
    - Evasion Artifact Elimination: 20% weight
    - Entropy Stability / Simplification: 10% weight
    """
    # 1. Indicator Recall (0 - 45 pts)
    recall_score = 45.0 * max(0.0, min(1.0, recall))

    # 2. AST Validity (0 or 25 pts)
    ast_score = 25.0 if ast_valid else 0.0

    # 3. Artifact Reduction (0 - 20 pts)
    art_before = orig_artifacts.get("total", 0)
    art_after = deob_artifacts.get("total", 0)
    if art_before > 0:
        ratio = (art_before - art_after) / art_before
        art_score = 20.0 * max(0.0, min(1.0, ratio))
    else:
        # If no artifacts were present initially, full credit if none introduced
        art_score = 20.0 if art_after == 0 else 10.0

    # 4. Entropy / Simplification (0 - 10 pts)
    if orig_entropy > 0:
        if deob_entropy <= orig_entropy:
            # Maintained or lowered entropy
            entropy_score = 10.0
        else:
            # Slight increase in entropy (e.g. from unpacking high-density base64)
            diff_ratio = (deob_entropy - orig_entropy) / orig_entropy
            entropy_score = 10.0 * max(0.0, 1.0 - diff_ratio)
    else:
        entropy_score = 10.0

    total_score = recall_score + ast_score + art_score + entropy_score
    return round(max(0.0, min(100.0, total_score)), 2)
