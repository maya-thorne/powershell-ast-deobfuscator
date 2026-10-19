"""
PowerShell AST Batch Forensic Automation Unified Public Facade.
Exposes high-level scan_directory, scan_files, runner, scanner, models,
and command-line interface execution dispatchers.
"""

import os
import sys
from typing import Any, Dict, List, Optional

from .batch_models import (
    BatchScanOptions,
    BatchSummary,
    FileScanResult,
    RiskTier,
    ScanStatus,
)
from .batch_runner import PowerShellBatchRunner
from .batch_scanner import PowerShellBatchScanner


def scan_directory(target_dir: str, **kwargs: Any) -> BatchSummary:
    """
    High-level entry point to scan an entire directory of PowerShell scripts in parallel.
    Accepts keyword arguments corresponding to BatchScanOptions fields.
    """
    options = BatchScanOptions(target_dir=target_dir, **kwargs)
    runner = PowerShellBatchRunner()
    return runner.run(options)


def scan_files(file_paths: List[str], **kwargs: Any) -> BatchSummary:
    """
    High-level entry point to scan an explicit list of script files in parallel.
    Accepts keyword arguments corresponding to BatchScanOptions fields.
    """
    target_dir = kwargs.pop("target_dir", ".")
    options = BatchScanOptions(target_dir=target_dir, **kwargs)
    runner = PowerShellBatchRunner()
    return runner.run_files(file_paths, options=options)


def run_batch_cli(args: Any) -> int:
    """
    Dispatches CLI batch scanning arguments to PowerShellBatchRunner and handles output.
    Returns 0 on successful scan, 1 on fatal error.
    """
    # 1. Determine target directory
    target_dir = getattr(args, "batch_dir", None)
    if not target_dir:
        target_dir = getattr(args, "batch", None)
    if not target_dir:
        target_dir = getattr(args, "scan_dir", None)
    if not target_dir and getattr(args, "input", None) and os.path.isdir(args.input):
        target_dir = args.input

    if not target_dir:
        sys.stderr.write("[-] Error: A target directory must be specified via --batch / --scan-dir.\n")
        return 1

    if not os.path.exists(target_dir):
        sys.stderr.write(f"[-] Error: Target path '{target_dir}' does not exist.\n")
        return 1

    # 2. Parse configuration options
    output_dir = getattr(args, "batch_output", None)
    max_workers = getattr(args, "batch_workers", 4) or 4
    raw_exts = getattr(args, "batch_exts", ".ps1,.psm1,.psd1,.bat,.cmd,.txt") or ".ps1,.psm1,.psd1,.bat,.cmd,.txt"
    file_extensions = [e.strip() for e in raw_exts.split(",") if e.strip()]

    recursive = getattr(args, "batch_recursive", True)
    timeout_sec = getattr(args, "batch_timeout", 30.0) or 30.0
    export_deobfuscated = bool(output_dir)
    export_iocs = getattr(args, "batch_export_iocs", False)
    min_risk_str = getattr(args, "batch_min_risk", "clean")
    min_risk = RiskTier.from_str(min_risk_str)

    report_format = getattr(args, "batch_format", "text") or "text"
    report_path = getattr(args, "batch_report", None)

    options = BatchScanOptions(
        target_dir=target_dir,
        output_dir=output_dir,
        max_workers=max_workers,
        file_extensions=file_extensions,
        recursive=recursive,
        timeout_sec=timeout_sec,
        export_deobfuscated=export_deobfuscated,
        export_iocs=export_iocs,
        min_risk=min_risk,
        report_format=report_format,
        report_path=report_path,
    )

    # 3. Execute batch runner
    runner = PowerShellBatchRunner()
    try:
        summary = runner.run(options)
    except Exception as ex:
        sys.stderr.write(f"[-] Fatal error during batch scan: {ex}\n")
        return 1

    # 4. Filter results if min_risk is elevated
    display_summary = summary
    if min_risk != RiskTier.CLEAN:
        filtered_results = [r for r in summary.results if r.risk_tier.is_at_least(min_risk)]
        display_summary = BatchSummary(
            target_dir=summary.target_dir,
            total_files_discovered=summary.total_files_discovered,
            total_files_scanned=summary.total_files_scanned,
            successful_scans=summary.successful_scans,
            skipped_files=summary.skipped_files,
            failed_scans=summary.failed_scans,
            timed_out_scans=summary.timed_out_scans,
            clean_count=summary.clean_count,
            suspicious_count=summary.suspicious_count,
            malicious_count=summary.malicious_count,
            total_duration_ms=summary.total_duration_ms,
            total_bytes_scanned=summary.total_bytes_scanned,
            total_urls_carved=summary.total_urls_carved,
            unique_urls=summary.unique_urls,
            total_amsi_bypasses=summary.total_amsi_bypasses,
            total_policy_bypasses=summary.total_policy_bypasses,
            results=filtered_results,
        )

    # 5. Format and present output
    fmt = report_format.lower()
    if fmt == "json":
        report_text = display_summary.to_json(indent=2)
    elif fmt == "markdown":
        report_text = display_summary.to_markdown()
    elif fmt == "csv":
        report_text = display_summary.to_csv()
    else:
        report_text = display_summary.to_text_table()

    if report_path:
        print(f"[+] Batch scan completed. Report ({report_format}) written to: {report_path}")
    else:
        try:
            print(report_text)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(report_text.encode("utf-8", errors="replace"))
            sys.stdout.buffer.write(b"\n")

    if export_deobfuscated and output_dir:
        print(f"[+] Deobfuscated scripts exported to: {output_dir}")

    if export_iocs:
        if output_dir:
            ioc_out = os.path.join(output_dir, "iocs.json")
        elif report_path:
            ioc_out = os.path.join(os.path.dirname(os.path.abspath(report_path)), "iocs.json")
        else:
            ioc_out = os.path.join(target_dir, "iocs.json")
        runner.save_iocs(summary, ioc_out)
        print(f"[+] Forensic IoCs exported to: {ioc_out}")

    return 0
