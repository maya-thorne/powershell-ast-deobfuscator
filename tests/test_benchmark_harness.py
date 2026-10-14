"""
Unit and integration tests for the automated PowerShell obfuscation benchmark harness.
Verifies corpus integrity, metrics evaluation, execution runner, formatters, and CLI flags.
"""

import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from src.benchmark import (
    CorpusBenchmarkSummary,
    CorpusSample,
    SampleBenchmarkResult,
    calculate_entropy,
    calculate_fidelity_score,
    calculate_indicator_recall,
    calculate_size_reduction,
    check_ast_validity,
    detect_artifacts,
    get_corpus,
    get_corpus_by_category,
    get_sample,
    run_benchmark,
    run_sample,
    save_report,
    to_json_report,
    to_markdown_report,
    to_text_report,
)
from src.cli import main


class TestBenchmarkCorpus(unittest.TestCase):
    """Verifies 30-sample corpus completeness and metadata integrity."""

    def setUp(self):
        self.corpus = get_corpus()

    def test_corpus_count_and_sample_types(self):
        self.assertEqual(len(self.corpus), 30)
        for s in self.corpus:
            self.assertIsInstance(s, CorpusSample)

    def test_unique_sample_identifiers(self):
        ids = [s.id for s in self.corpus]
        self.assertEqual(len(ids), len(set(ids)), "Corpus sample IDs must be strictly unique")
        for i, s_id in enumerate(ids, start=1):
            expected_id = f"SAMPLE-{i:02d}"
            self.assertEqual(s_id, expected_id)

    def test_non_empty_metadata_fields(self):
        for s in self.corpus:
            self.assertTrue(s.id.strip())
            self.assertTrue(s.name.strip())
            self.assertTrue(s.category.strip())
            self.assertTrue(s.description.strip())
            self.assertTrue(s.obfuscated_script.strip())
            self.assertIsInstance(s.expected_indicators, list)
            self.assertGreater(len(s.expected_indicators), 0)
            self.assertIsInstance(s.target_properties, dict)

    def test_category_distribution_and_coverage(self):
        categories = {s.category for s in self.corpus}
        self.assertEqual(len(categories), 10, "Corpus must span exactly 10 distinct categories")
        for cat in categories:
            samples_in_cat = get_corpus_by_category(cat)
            self.assertEqual(len(samples_in_cat), 3, f"Category '{cat}' must have exactly 3 samples")

    def test_get_sample_by_id(self):
        sample = get_sample("SAMPLE-01")
        self.assertIsNotNone(sample)
        self.assertEqual(sample.id, "SAMPLE-01")

        # Case-insensitive lookup test
        sample_lower = get_sample("sample-01")
        self.assertIsNotNone(sample_lower)
        self.assertEqual(sample_lower.id, "SAMPLE-01")

        # Non-existent ID test
        self.assertIsNone(get_sample("SAMPLE-999"))

    def test_get_corpus_by_category_filtering(self):
        samples = get_corpus_by_category("Format Operator Shuffle")
        self.assertEqual(len(samples), 3)
        self.assertTrue(all(s.category == "Format Operator Shuffle" for s in samples))

        # Case-insensitive filtering
        samples_lower = get_corpus_by_category("format operator shuffle")
        self.assertEqual(len(samples_lower), 3)

        # Empty result on unknown category
        unknown = get_corpus_by_category("NonExistentCategory")
        self.assertEqual(len(unknown), 0)


class TestBenchmarkMetrics(unittest.TestCase):
    """Verifies metric calculations: entropy, artifacts, recall, AST validity, and fidelity."""

    def test_entropy_calculation(self):
        # Empty text
        self.assertEqual(calculate_entropy(""), 0.0)

        # Uniform text has zero entropy
        self.assertEqual(calculate_entropy("aaaaaaa"), 0.0)

        # Multi-character text has positive entropy
        ent1 = calculate_entropy("Invoke-Expression 'whoami'")
        self.assertGreater(ent1, 3.0)

        # Base64 string has positive entropy
        ent2 = calculate_entropy("SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBu")
        self.assertGreater(ent2, 3.0)

    def test_size_reduction(self):
        self.assertEqual(calculate_size_reduction("", ""), 0.0)
        self.assertEqual(calculate_size_reduction("1234", "1234"), 0.0)
        self.assertEqual(calculate_size_reduction("1234", "12"), 50.0)
        self.assertEqual(calculate_size_reduction("12", "1234"), -100.0)

    def test_detect_artifacts(self):
        script = (
            "In`voke-Exp`ression "
            "('{1}{0}' -f 'ex','i') "
            "powershell.exe -enc aGVsbG8= "
            "'xaxeix'[5,4,0] "
            "$((('nested'))) "
            "InVoKe-ExPrEsSiOn"
        )
        artifacts = detect_artifacts(script)
        self.assertGreaterEqual(artifacts["backticks"], 2)
        self.assertGreaterEqual(artifacts["format_operators"], 1)
        self.assertGreaterEqual(artifacts["base64_flags"], 1)
        self.assertGreaterEqual(artifacts["shuffled_indices"], 1)
        self.assertGreaterEqual(artifacts["nested_subexpressions"], 1)
        self.assertGreaterEqual(artifacts["casing_anomalies"], 1)
        self.assertGreater(artifacts["total"], 5)

        # Empty script detection
        empty_art = detect_artifacts("")
        self.assertEqual(empty_art["total"], 0)

    def test_calculate_indicator_recall(self):
        expected = ["Invoke-Expression", "Get-Process", "calc.exe"]
        script_full = "Invoke-Expression (Get-Process 'calc.exe')"
        recall, rec, miss = calculate_indicator_recall(expected, script_full)
        self.assertEqual(recall, 1.0)
        self.assertEqual(len(rec), 3)
        self.assertEqual(len(miss), 0)

        script_partial = "Invoke-Expression (Get-Service)"
        recall_part, rec_part, miss_part = calculate_indicator_recall(expected, script_partial)
        self.assertAlmostEqual(recall_part, 1 / 3, places=2)
        self.assertIn("Invoke-Expression", rec_part)
        self.assertIn("Get-Process", miss_part)

        # Empty expected indicators
        rec_empty, _, _ = calculate_indicator_recall([], "anything")
        self.assertEqual(rec_empty, 1.0)

    def test_check_ast_validity(self):
        # Valid PowerShell
        valid_script = "Invoke-Expression 'Get-Process'"
        is_valid, nodes, err = check_ast_validity(valid_script)
        self.assertTrue(is_valid)
        self.assertGreater(nodes, 0)
        self.assertIsNone(err)

        # Invalid PowerShell (unclosed parenthesis syntax error)
        invalid_script = "Invoke-Expression ("
        is_invalid, nodes_inv, err_inv = check_ast_validity(invalid_script)
        self.assertFalse(is_invalid)
        self.assertIsNotNone(err_inv)

        # Empty script
        is_empty, _, _ = check_ast_validity("")
        self.assertFalse(is_empty)

    def test_calculate_fidelity_score(self):
        # Perfect recovery with artifact elimination
        score_100 = calculate_fidelity_score(
            recall=1.0,
            ast_valid=True,
            orig_artifacts={"total": 5},
            deob_artifacts={"total": 0},
            orig_entropy=4.5,
            deob_entropy=4.0,
        )
        self.assertEqual(score_100, 100.0)

        # Degraded recovery
        score_degraded = calculate_fidelity_score(
            recall=0.5,
            ast_valid=True,
            orig_artifacts={"total": 5},
            deob_artifacts={"total": 5},
            orig_entropy=4.5,
            deob_entropy=4.5,
        )
        self.assertLess(score_degraded, 80.0)

        # Invalid AST severely penalizes score
        score_invalid_ast = calculate_fidelity_score(
            recall=1.0,
            ast_valid=False,
            orig_artifacts={"total": 0},
            deob_artifacts={"total": 0},
            orig_entropy=4.0,
            deob_entropy=4.0,
        )
        self.assertLessEqual(score_invalid_ast, 75.0)


class TestBenchmarkRunner(unittest.TestCase):
    """Verifies end-to-end execution runner across single samples and the complete 30-sample corpus."""

    def test_run_single_sample(self):
        sample = get_sample("SAMPLE-01")
        self.assertIsNotNone(sample)
        result = run_sample(sample)
        self.assertIsInstance(result, SampleBenchmarkResult)
        self.assertEqual(result.sample_id, "SAMPLE-01")
        self.assertTrue(result.success)
        self.assertTrue(result.ast_valid)
        self.assertEqual(result.indicator_recall, 1.0)
        self.assertGreater(result.fidelity_score, 80.0)
        self.assertGreater(result.execution_time_ms, 0.0)

    def test_run_full_30_sample_corpus(self):
        summary = run_benchmark()
        self.assertIsInstance(summary, CorpusBenchmarkSummary)
        self.assertEqual(summary.total_samples, 30)
        self.assertEqual(summary.successful_samples, 30)
        self.assertEqual(summary.failed_samples, 0)
        self.assertEqual(summary.ast_validity_rate, 1.0)
        self.assertEqual(summary.average_indicator_recall, 1.0)
        self.assertGreaterEqual(summary.average_fidelity_score, 85.0)
        self.assertGreater(summary.total_execution_time_ms, 0.0)
        self.assertEqual(len(summary.results), 30)
        self.assertEqual(len(summary.category_summaries), 10)

    def test_empty_corpus_run(self):
        summary = run_benchmark(corpus=[])
        self.assertEqual(summary.total_samples, 0)
        self.assertEqual(summary.successful_samples, 0)
        self.assertEqual(summary.failed_samples, 0)
        self.assertEqual(summary.average_fidelity_score, 0.0)


class TestBenchmarkReportFormatters(unittest.TestCase):
    """Verifies report generation across Text, JSON, and Markdown channels, plus persistence."""

    def setUp(self):
        sample = get_sample("SAMPLE-04")
        self.summary = run_benchmark(corpus=[sample])

    def test_to_text_report(self):
        report = to_text_report(self.summary)
        self.assertIn("POWERSHELL AST DEOBFUSCATOR BENCHMARK REPORT", report)
        self.assertIn("CATEGORY BREAKDOWN:", report)
        self.assertIn("SAMPLE EXECUTION MATRIX:", report)
        self.assertIn("SAMPLE-04", report)

    def test_to_json_report(self):
        json_report = to_json_report(self.summary)
        parsed = json.loads(json_report)
        self.assertEqual(parsed["total_samples"], 1)
        self.assertEqual(parsed["successful_samples"], 1)
        self.assertIn("results", parsed)
        self.assertIn("category_summaries", parsed)
        self.assertEqual(parsed["results"][0]["sample_id"], "SAMPLE-04")

    def test_to_markdown_report(self):
        md_report = to_markdown_report(self.summary)
        self.assertIn("# PowerShell AST Deobfuscator Benchmark Report", md_report)
        self.assertIn("## Executive Summary", md_report)
        self.assertIn("## Category Performance Breakdown", md_report)
        self.assertIn("## Detailed Sample Results", md_report)
        self.assertIn("| `SAMPLE-04` |", md_report)

    def test_save_report(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dest_path = os.path.join(tmp_dir, "nested", "benchmark_report.md")
            content = "# Sample Report Content\n100% OK"
            save_report(content, dest_path)
            self.assertTrue(os.path.isfile(dest_path))
            with open(dest_path, "r", encoding="utf-8") as f:
                saved = f.read()
            self.assertEqual(saved.strip(), content.strip())


class TestBenchmarkCLI(unittest.TestCase):
    """Verifies CLI flags for benchmark harness invocation."""

    def test_cli_benchmark_default(self):
        with patch("sys.argv", ["pwsh-ast", "--benchmark"]), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_out:
            main()
            output = mock_out.getvalue()
            self.assertIn("POWERSHELL AST DEOBFUSCATOR BENCHMARK REPORT", output)
            self.assertIn("Total Samples Tested     : 30", output)

    def test_cli_benchmark_single_sample(self):
        with patch("sys.argv", ["pwsh-ast", "--benchmark-sample", "SAMPLE-07"]), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_out:
            main()
            output = mock_out.getvalue()
            self.assertIn("Total Samples Tested     : 1", output)
            self.assertIn("SAMPLE-07", output)

    def test_cli_benchmark_category(self):
        with patch(
            "sys.argv",
            ["pwsh-ast", "--benchmark-category", "Format Operator Shuffle"],
        ), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            main()
            output = mock_out.getvalue()
            self.assertIn("Total Samples Tested     : 3", output)
            self.assertIn("SAMPLE-04", output)
            self.assertIn("SAMPLE-05", output)
            self.assertIn("SAMPLE-06", output)

    def test_cli_benchmark_format_json(self):
        with patch(
            "sys.argv",
            ["pwsh-ast", "--benchmark-sample", "SAMPLE-10", "--benchmark-format", "json"],
        ), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            main()
            output = mock_out.getvalue()
            parsed = json.loads(output)
            self.assertEqual(parsed["total_samples"], 1)
            self.assertEqual(parsed["results"][0]["sample_id"], "SAMPLE-10")

    def test_cli_benchmark_report_persistence(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = os.path.join(tmp_dir, "report.md")
            with patch(
                "sys.argv",
                [
                    "pwsh-ast",
                    "--benchmark-sample",
                    "SAMPLE-01",
                    "--benchmark-format",
                    "markdown",
                    "--benchmark-report",
                    report_file,
                ],
            ), patch("sys.stdout", new_callable=io.StringIO):
                main()
            self.assertTrue(os.path.isfile(report_file))
            with open(report_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("# PowerShell AST Deobfuscator Benchmark Report", content)

    def test_cli_benchmark_invalid_sample(self):
        with patch("sys.argv", ["pwsh-ast", "--benchmark-sample", "SAMPLE-INVALID"]), patch(
            "sys.stderr", new_callable=io.StringIO
        ) as mock_err, self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("not found", mock_err.getvalue())

    def test_cli_benchmark_invalid_category(self):
        with patch("sys.argv", ["pwsh-ast", "--benchmark-category", "NonExistentCat"]), patch(
            "sys.stderr", new_callable=io.StringIO
        ) as mock_err, self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("not found or empty", mock_err.getvalue())

    def test_cli_no_input_prints_help(self):
        with patch("sys.argv", ["pwsh-ast"]), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_out:
            main()
            output = mock_out.getvalue()
            self.assertIn("usage:", output.lower())


if __name__ == "__main__":
    unittest.main()
