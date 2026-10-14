"""
PowerShell Deobfuscation Automated Benchmark Runner & Report Formatter.
Executes batch analysis over corpus samples, measures fidelity and performance,
and formats telemetry across Text, JSON, and Markdown report channels.
"""

from dataclasses import asdict
import json
import os
import time
from typing import Dict, List, Optional

from .benchmark_corpus import CorpusSample, get_corpus
from .benchmark_metrics import (
    CorpusBenchmarkSummary,
    SampleBenchmarkResult,
    calculate_entropy,
    calculate_fidelity_score,
    calculate_indicator_recall,
    calculate_size_reduction,
    check_ast_validity,
    detect_artifacts,
)
from .deobfuscator_engine import PowerShellDeobfuscator


def run_sample(
    sample: CorpusSample,
    deobfuscator: Optional[PowerShellDeobfuscator] = None,
) -> SampleBenchmarkResult:
    """
    Executes deobfuscation and telemetry measurement for a single corpus sample.
    """
    if deobfuscator is None:
        deobfuscator = PowerShellDeobfuscator()

    start_time = time.perf_counter()
    original_script = sample.obfuscated_script

    orig_entropy = calculate_entropy(original_script)
    orig_length = len(original_script)
    orig_artifacts = detect_artifacts(original_script)

    error_msg: Optional[str] = None
    try:
        deob_script = deobfuscator.deobfuscate(original_script)
    except Exception as ex:
        deob_script = original_script
        error_msg = f"Deobfuscation failed: {ex}"

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    deob_entropy = calculate_entropy(deob_script)
    deob_length = len(deob_script)
    deob_artifacts = detect_artifacts(deob_script)

    entropy_red = round(orig_entropy - deob_entropy, 4)
    size_red_pct = calculate_size_reduction(original_script, deob_script)
    artifacts_removed = orig_artifacts.get("total", 0) - deob_artifacts.get("total", 0)

    recall, recovered_ind, missing_ind = calculate_indicator_recall(
        sample.expected_indicators,
        deob_script,
    )
    ast_valid, node_count, ast_err = check_ast_validity(deob_script)
    if ast_err and not error_msg:
        error_msg = f"AST validity check failed: {ast_err}"

    fidelity = calculate_fidelity_score(
        recall=recall,
        ast_valid=ast_valid,
        orig_artifacts=orig_artifacts,
        deob_artifacts=deob_artifacts,
        orig_entropy=orig_entropy,
        deob_entropy=deob_entropy,
    )

    success = ast_valid and (recall >= 0.9999) and (error_msg is None)

    return SampleBenchmarkResult(
        sample_id=sample.id,
        name=sample.name,
        category=sample.category,
        original_script=original_script,
        deobfuscated_script=deob_script,
        original_entropy=orig_entropy,
        deobfuscated_entropy=deob_entropy,
        entropy_reduction=entropy_red,
        original_length=orig_length,
        deobfuscated_length=deob_length,
        size_reduction_pct=size_red_pct,
        original_artifacts=orig_artifacts,
        deobfuscated_artifacts=deob_artifacts,
        artifacts_removed=artifacts_removed,
        expected_indicators=sample.expected_indicators,
        recovered_indicators=recovered_ind,
        missing_indicators=missing_ind,
        indicator_recall=recall,
        ast_valid=ast_valid,
        ast_node_count=node_count,
        fidelity_score=fidelity,
        execution_time_ms=round(elapsed_ms, 2),
        success=success,
        error_message=error_msg,
    )


def run_benchmark(
    corpus: Optional[List[CorpusSample]] = None,
    deobfuscator: Optional[PowerShellDeobfuscator] = None,
) -> CorpusBenchmarkSummary:
    """
    Executes automated benchmark evaluation across the provided corpus
    (defaults to the canonical 30-sample benchmark corpus).
    """
    if corpus is None:
        corpus = get_corpus()
    if deobfuscator is None:
        deobfuscator = PowerShellDeobfuscator()

    results: List[SampleBenchmarkResult] = []
    total_time_ms = 0.0

    for sample in corpus:
        res = run_sample(sample, deobfuscator=deobfuscator)
        results.append(res)
        total_time_ms += res.execution_time_ms

    total_samples = len(results)
    if total_samples == 0:
        return CorpusBenchmarkSummary(
            total_samples=0,
            successful_samples=0,
            failed_samples=0,
            average_fidelity_score=0.0,
            average_indicator_recall=0.0,
            average_entropy_reduction=0.0,
            average_size_reduction_pct=0.0,
            ast_validity_rate=0.0,
            total_execution_time_ms=0.0,
            results=[],
            category_summaries={},
        )

    successful = sum(1 for r in results if r.success)
    failed = total_samples - successful
    avg_fidelity = sum(r.fidelity_score for r in results) / total_samples
    avg_recall = sum(r.indicator_recall for r in results) / total_samples
    avg_entropy_red = sum(r.entropy_reduction for r in results) / total_samples
    avg_size_red = sum(r.size_reduction_pct for r in results) / total_samples
    ast_valid_rate = sum(1 for r in results if r.ast_valid) / total_samples

    # Compute category-level aggregations
    category_map: Dict[str, List[SampleBenchmarkResult]] = {}
    for r in results:
        category_map.setdefault(r.category, []).append(r)

    category_summaries: Dict[str, Dict[str, float]] = {}
    for cat, cat_results in category_map.items():
        cat_count = len(cat_results)
        cat_success = sum(1 for r in cat_results if r.success)
        category_summaries[cat] = {
            "sample_count": float(cat_count),
            "success_rate": round((cat_success / cat_count) * 100.0, 1),
            "average_fidelity": round(sum(r.fidelity_score for r in cat_results) / cat_count, 2),
            "average_recall": round((sum(r.indicator_recall for r in cat_results) / cat_count) * 100.0, 1),
            "average_time_ms": round(sum(r.execution_time_ms for r in cat_results) / cat_count, 2),
        }

    return CorpusBenchmarkSummary(
        total_samples=total_samples,
        successful_samples=successful,
        failed_samples=failed,
        average_fidelity_score=round(avg_fidelity, 2),
        average_indicator_recall=round(avg_recall, 4),
        average_entropy_reduction=round(avg_entropy_red, 4),
        average_size_reduction_pct=round(avg_size_red, 2),
        ast_validity_rate=round(ast_valid_rate, 4),
        total_execution_time_ms=round(total_time_ms, 2),
        results=results,
        category_summaries=category_summaries,
    )


def to_text_report(summary: CorpusBenchmarkSummary) -> str:
    """
    Renders benchmark summary into human-readable ASCII console text format.
    """
    lines: List[str] = [
        "=" * 84,
        "              POWERSHELL AST DEOBFUSCATOR BENCHMARK REPORT",
        "=" * 84,
        f"Total Samples Tested     : {summary.total_samples}",
        f"Successful Deobfuscations : {summary.successful_samples} ({summary.successful_samples / max(summary.total_samples, 1) * 100.0:.1f}%)",
        f"Failed Samples           : {summary.failed_samples}",
        f"Average Fidelity Score   : {summary.average_fidelity_score:.2f} / 100.00",
        f"Average Indicator Recall : {summary.average_indicator_recall * 100.0:.2f}%",
        f"AST Validity Rate        : {summary.ast_validity_rate * 100.0:.2f}%",
        f"Average Entropy Delta    : {summary.average_entropy_reduction:+.4f} bits",
        f"Average Size Delta       : {summary.average_size_reduction_pct:+.2f}%",
        f"Total Benchmark Time     : {summary.total_execution_time_ms:.2f} ms",
        "-" * 84,
        "CATEGORY BREAKDOWN:",
        f"{'Category':<42} {'Count':<6} {'Success':<8} {'Fidelity':<10} {'Recall':<8} {'Time(ms)'}",
        "-" * 84,
    ]

    for cat, meta in sorted(summary.category_summaries.items()):
        lines.append(
            f"{cat:<42} {int(meta['sample_count']):<6} "
            f"{meta['success_rate']:>5.1f}%   "
            f"{meta['average_fidelity']:>6.2f}     "
            f"{meta['average_recall']:>5.1f}%  "
            f"{meta['average_time_ms']:>7.2f}"
        )

    lines.extend([
        "-" * 84,
        "SAMPLE EXECUTION MATRIX:",
        f"{'ID':<10} {'Status':<6} {'Recall':<8} {'AST':<5} {'Fidelity':<10} {'Time(ms)':<9} {'Name'}",
        "-" * 84,
    ])

    for r in summary.results:
        status_sym = "[OK]" if r.success else "[FAIL]"
        ast_sym = "YES" if r.ast_valid else "NO"
        lines.append(
            f"{r.sample_id:<10} {status_sym:<6} {r.indicator_recall * 100.0:>5.1f}%  "
            f"{ast_sym:<5} {r.fidelity_score:>6.2f}    "
            f"{r.execution_time_ms:>6.2f}    {r.name}"
        )

    lines.append("=" * 84)
    return "\n".join(lines)


def to_json_report(summary: CorpusBenchmarkSummary, indent: int = 2) -> str:
    """
    Serializes complete benchmark telemetry into structured JSON format.
    """
    data = asdict(summary)
    return json.dumps(data, indent=indent, ensure_ascii=False)


def to_markdown_report(summary: CorpusBenchmarkSummary) -> str:
    """
    Renders benchmark summary into GitHub-Flavored Markdown report with tables.
    """
    success_rate = (summary.successful_samples / max(summary.total_samples, 1)) * 100.0
    lines: List[str] = [
        "# PowerShell AST Deobfuscator Benchmark Report",
        "",
        "## Executive Summary",
        "",
        f"- **Total Corpus Samples**: `{summary.total_samples}`",
        f"- **Success Rate**: `{success_rate:.1f}%` ({summary.successful_samples}/{summary.total_samples})",
        f"- **Average Composite Fidelity**: `{summary.average_fidelity_score:.2f} / 100.00`",
        f"- **Average Indicator Recall**: `{summary.average_indicator_recall * 100.0:.2f}%`",
        f"- **AST Validity Rate**: `{summary.ast_validity_rate * 100.0:.2f}%`",
        f"- **Average Entropy Delta**: `{summary.average_entropy_reduction:+.4f} bits`",
        f"- **Average Size Delta**: `{summary.average_size_reduction_pct:+.2f}%`",
        f"- **Total Benchmark Wall Time**: `{summary.total_execution_time_ms:.2f} ms`",
        "",
        "## Category Performance Breakdown",
        "",
        "| Category | Samples | Success Rate | Avg Fidelity | Avg Recall | Avg Latency |",
        "|---|---|---|---|---|---|",
    ]

    for cat, meta in sorted(summary.category_summaries.items()):
        lines.append(
            f"| **{cat}** | {int(meta['sample_count'])} | {meta['success_rate']:.1f}% | "
            f"{meta['average_fidelity']:.2f} | {meta['average_recall']:.1f}% | "
            f"{meta['average_time_ms']:.2f} ms |"
        )

    lines.extend([
        "",
        "## Detailed Sample Results",
        "",
        "| ID | Sample Name | Category | Status | Recall | AST Valid | Fidelity | Time |",
        "|---|---|---|---|---|---|---|---|",
    ])

    for r in summary.results:
        status_icon = "PASS" if r.success else "FAIL"
        ast_icon = "Valid" if r.ast_valid else "Invalid"
        lines.append(
            f"| `{r.sample_id}` | {r.name} | {r.category} | {status_icon} | "
            f"{r.indicator_recall * 100.0:.1f}% | {ast_icon} | "
            f"**{r.fidelity_score:.2f}** | {r.execution_time_ms:.2f} ms |"
        )

    lines.append("")
    return "\n".join(lines)


def save_report(report_content: str, destination_path: str) -> None:
    """
    Persists benchmark report content to target file path using UTF-8 encoding.
    Creates parent directories if necessary.
    """
    parent = os.path.dirname(destination_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(destination_path, "w", encoding="utf-8") as f:
        f.write(report_content)
        if not report_content.endswith("\n"):
            f.write("\n")
