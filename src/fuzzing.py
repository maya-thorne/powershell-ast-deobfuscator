"""
PowerShell AST Deobfuscation Regression Fuzzing Subsystem.
Unified facade exposing script mutator, fuzzing runner, test cases, and reporting utilities.
"""

from typing import List, Optional

from .fuzz_models import (
    FuzzExecutionResult,
    FuzzMutationRecord,
    FuzzSeverity,
    FuzzStatus,
    FuzzSummary,
    FuzzTestCase,
    MutationStrategy,
)
from .fuzz_mutator import PowerShellScriptMutator
from .fuzz_runner import PowerShellFuzzRunner


def run_fuzz_harness(
    iterations: int = 50,
    seed: int = 42,
    strategies: Optional[List[MutationStrategy]] = None,
    use_corpus: bool = True,
    custom_samples: Optional[List[str]] = None,
    enable_shrink: bool = True,
) -> FuzzSummary:
    """
    Executes automated stress fuzzing suite across N iterations with reproducible seed.
    """
    runner = PowerShellFuzzRunner(seed=seed, enable_shrink=enable_shrink)
    return runner.run_fuzz_harness(
        iterations=iterations,
        strategies=strategies,
        use_corpus=use_corpus,
        custom_samples=custom_samples,
    )


def mutate_script(
    script: str,
    seed: Optional[int] = None,
    strategies: Optional[List[MutationStrategy]] = None,
    num_mutations: int = 3,
    name: str = "custom",
) -> FuzzTestCase:
    """
    Generates a mutated variant of a single PowerShell script string.
    """
    mutator = PowerShellScriptMutator(seed=seed)
    return mutator.generate_mutated_case(
        original_code=script,
        name=name,
        strategies=strategies,
        num_mutations=num_mutations,
    )


def fuzz_script(
    script: str,
    seed: int = 42,
    enable_shrink: bool = True,
) -> FuzzExecutionResult:
    """
    Executes a single test script through the compiler fuzzing pipeline.
    """
    runner = PowerShellFuzzRunner(seed=seed, enable_shrink=enable_shrink)
    test_case = FuzzTestCase(
        test_id=f"fuzz_{seed:06d}_direct",
        seed=seed,
        base_name="direct_script",
        original_code=script,
        mutated_code=script,
    )
    return runner.run_case(test_case)


def to_text_report(summary: FuzzSummary) -> str:
    """Renders plain text fuzzing summary report."""
    runner = PowerShellFuzzRunner()
    return runner.to_text_report(summary)


def to_markdown_report(summary: FuzzSummary) -> str:
    """Renders markdown fuzzing summary report."""
    runner = PowerShellFuzzRunner()
    return runner.to_markdown_report(summary)


def to_json_report(summary: FuzzSummary) -> str:
    """Renders structured JSON fuzzing summary report."""
    runner = PowerShellFuzzRunner()
    return runner.to_json_report(summary)


def save_report(report_content: str, file_path: str) -> None:
    """Saves fuzzing report to a destination path."""
    runner = PowerShellFuzzRunner()
    runner.save_report(report_content, file_path)


__all__ = [
    "MutationStrategy",
    "FuzzStatus",
    "FuzzSeverity",
    "FuzzMutationRecord",
    "FuzzTestCase",
    "FuzzExecutionResult",
    "FuzzSummary",
    "PowerShellScriptMutator",
    "PowerShellFuzzRunner",
    "run_fuzz_harness",
    "mutate_script",
    "fuzz_script",
    "to_text_report",
    "to_markdown_report",
    "to_json_report",
    "save_report",
]
