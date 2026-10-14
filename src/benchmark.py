"""
PowerShell Obfuscation Benchmark Suite & Automated Accuracy Runner.
Curated 30-sample corpus, multi-dimensional fidelity telemetry, and report generator.
"""

from .benchmark_corpus import (
    CorpusSample,
    get_corpus,
    get_corpus_by_category,
    get_sample,
)
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
from .benchmark_runner import (
    run_benchmark,
    run_sample,
    save_report,
    to_json_report,
    to_markdown_report,
    to_text_report,
)

__all__ = [
    "CorpusSample",
    "get_corpus",
    "get_sample",
    "get_corpus_by_category",
    "SampleBenchmarkResult",
    "CorpusBenchmarkSummary",
    "calculate_entropy",
    "calculate_size_reduction",
    "detect_artifacts",
    "calculate_indicator_recall",
    "check_ast_validity",
    "calculate_fidelity_score",
    "run_sample",
    "run_benchmark",
    "to_text_report",
    "to_json_report",
    "to_markdown_report",
    "save_report",
]
