"""
PowerShell AST Batch Parallel Analysis & Forensic Execution Runner.
Coordinates multithreaded directory scans, per-script timeouts, error isolation,
AST deobfuscation convergence, entropy analysis, URL carving, threat detection,
RiskTier classification, output export, and multi-format report generation.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .amsi_etw_detector import PowerShellAmsiEtwDetector
from .batch_models import BatchScanOptions, BatchSummary, FileScanResult, RiskTier, ScanStatus
from .batch_scanner import PowerShellBatchScanner
from .benchmark_metrics import calculate_entropy, check_ast_validity
from .deobfuscator_engine import PowerShellDeobfuscator
from .webclient_tracer import carve_all_urls


class PowerShellBatchRunner:
    """
    Mass-scale parallel script runner and forensic analyzer for PowerShell.
    Orchestrates ThreadPoolExecutor workers with strict error boundaries and timeouts.
    """

    # Memory allocation and injection API keywords for risk scoring
    MEMORY_INJECTION_APIS = [
        "virtualalloc",
        "virtualprotect",
        "createthread",
        "createremotethread",
        "writeprocessmemory",
        "queueuserapc",
        "rtlmovememory",
        "marshal.getdelegateforfunctionpointer",
    ]

    def __init__(self, scanner: Optional[PowerShellBatchScanner] = None) -> None:
        self.scanner = scanner or PowerShellBatchScanner()

    def run(self, options: BatchScanOptions) -> BatchSummary:
        """
        Executes parallel batch scan across all discovered files in options.target_dir.
        Returns aggregated BatchSummary telemetry.
        """
        discovered = self.scanner.discover_files(options)
        return self._execute_batch(discovered, options, options.target_dir)

    def run_files(
        self,
        file_paths: List[str],
        options: Optional[BatchScanOptions] = None,
    ) -> BatchSummary:
        """
        Executes parallel scan across an explicit list of file paths.
        """
        opts = options or BatchScanOptions(target_dir=".")
        discovered = [
            (os.path.abspath(p), os.path.basename(p))
            for p in file_paths
            if os.path.exists(p) and os.path.isfile(p)
        ]
        return self._execute_batch(discovered, opts, opts.target_dir)

    def _execute_batch(
        self,
        discovered: List[Tuple[str, str]],
        options: BatchScanOptions,
        target_dir: str,
    ) -> BatchSummary:
        """Internal parallel execution engine driving ThreadPoolExecutor over discovered files."""
        start_time = time.perf_counter()
        total_discovered = len(discovered)

        summary = BatchSummary(
            target_dir=target_dir,
            total_files_discovered=total_discovered,
        )

        if not discovered:
            summary.total_duration_ms = (time.perf_counter() - start_time) * 1000.0
            return summary

        # Step 2: Parallel execution with ThreadPoolExecutor
        max_workers = max(1, min(options.max_workers, 32))
        file_results: List[FileScanResult] = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_list = [
                (executor.submit(self._scan_single_file, abs_path, rel_path, options), abs_path, rel_path)
                for abs_path, rel_path in discovered
            ]

            for future, abs_path, rel_path in future_list:
                try:
                    res = future.result(timeout=options.timeout_sec)
                    file_results.append(res)
                except TimeoutError:
                    timeout_res = FileScanResult(
                        file_path=abs_path,
                        relative_path=rel_path,
                        status=ScanStatus.TIMEOUT,
                        risk_tier=RiskTier.SUSPICIOUS,
                        risk_score=30.0,
                        risk_reasons=[f"Deobfuscation execution timed out after {options.timeout_sec:.1f}s"],
                        duration_ms=options.timeout_sec * 1000.0,
                        error_message=f"Scan timed out after {options.timeout_sec:.1f}s",
                    )
                    file_results.append(timeout_res)
                except Exception as ex:
                    failed_res = FileScanResult(
                        file_path=abs_path,
                        relative_path=rel_path,
                        status=ScanStatus.FAILED,
                        error_message=str(ex),
                        risk_tier=RiskTier.CLEAN,
                    )
                    file_results.append(failed_res)

        # Sort results deterministically by relative path
        file_results.sort(key=lambda r: r.relative_path.lower())

        # Step 3: Aggregate results into BatchSummary
        unique_urls_set = set()
        for r in file_results:
            summary.total_files_scanned += 1
            summary.total_bytes_scanned += r.file_size
            summary.total_duration_ms += r.duration_ms
            summary.total_urls_carved += len(r.carved_urls)
            for url in r.carved_urls:
                unique_urls_set.add(url)
            summary.total_amsi_bypasses += r.amsi_etw_count
            summary.total_policy_bypasses += r.policy_bypass_count

            if r.status == ScanStatus.SUCCESS:
                summary.successful_scans += 1
            elif r.status == ScanStatus.TIMEOUT:
                summary.timed_out_scans += 1
            elif r.status == ScanStatus.SKIPPED:
                summary.skipped_files += 1
            elif r.status == ScanStatus.FAILED:
                summary.failed_scans += 1

            if r.risk_tier == RiskTier.MALICIOUS:
                summary.malicious_count += 1
            elif r.risk_tier == RiskTier.SUSPICIOUS:
                summary.suspicious_count += 1
            elif r.risk_tier == RiskTier.CLEAN:
                summary.clean_count += 1

        summary.unique_urls = sorted(list(unique_urls_set))
        summary.results = file_results

        # Real wall-clock duration of overall batch run
        summary.total_duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Step 4: Optional report generation and IoC export
        if options.report_path:
            self.save_report(summary, options.report_path, options.report_format)

        if options.export_iocs and options.output_dir:
            ioc_path = os.path.join(options.output_dir, "iocs.json")
            self.save_iocs(summary, ioc_path)

        return summary

    def _scan_single_file(
        self,
        abs_path: str,
        rel_path: str,
        options: BatchScanOptions,
    ) -> FileScanResult:
        """
        Executes isolated deobfuscation and forensic scanning on an individual script.
        Captures all exceptions internally to guarantee error isolation.
        """
        item_start = time.perf_counter()

        # Step A: Read raw file safely
        try:
            raw_script, sha256_hash, encoding_used, file_size = self.scanner.read_file_safe(
                abs_path, max_size_bytes=options.max_file_size_bytes
            )
        except Exception as ex:
            return FileScanResult(
                file_path=abs_path,
                relative_path=rel_path,
                status=ScanStatus.FAILED,
                error_message=f"Read failure: {ex}",
                duration_ms=(time.perf_counter() - item_start) * 1000.0,
            )

        orig_len = len(raw_script)
        orig_entropy = calculate_entropy(raw_script)

        # Step B: Execute multi-pass AST deobfuscator
        deobfuscator = PowerShellDeobfuscator(
            detect_amsi_etw=True,
            simulate_policy=True,
            decompress_streams=True,
            unwrap_subexpr=True,
            normalize_casing=True,
            unwrap_iex=True,
        )

        try:
            deobfuscated_script = deobfuscator.deobfuscate(raw_script)
            scan_status = ScanStatus.SUCCESS
            error_msg: Optional[str] = None
        except Exception as ex:
            deobfuscated_script = raw_script
            scan_status = ScanStatus.FAILED
            error_msg = f"Deobfuscation failure: {ex}"

        deob_len = len(deobfuscated_script)
        deob_entropy = calculate_entropy(deobfuscated_script)
        entropy_reduction = round(orig_entropy - deob_entropy, 4)
        size_reduction_pct = (
            round(((orig_len - deob_len) / orig_len) * 100.0, 2) if orig_len > 0 else 0.0
        )

        # Step C: Extract forensic telemetry and indicators
        carved_targets = carve_all_urls(deobfuscated_script)
        if not carved_targets and deobfuscated_script != raw_script:
            carved_targets = carve_all_urls(raw_script)

        carved_urls: List[str] = sorted(list({t.url for t in carved_targets}))

        amsi_findings = deobfuscator.last_amsi_etw_findings or []
        amsi_dicts = [f.to_dict() for f in amsi_findings]
        amsi_count = len(amsi_findings)

        policy_summary = deobfuscator.last_policy_summary
        policy_findings = policy_summary.findings if policy_summary else []
        policy_dicts = [f.to_dict() for f in policy_findings]
        policy_count = len(policy_findings)

        encoded_layers_count = len(deobfuscator.last_layers)
        comp_layers_count = len(deobfuscator.last_compression_layers)
        iex_layers_count = len(deobfuscator.last_iex_layers)

        # AST validity verification
        ast_valid, ast_node_count, _ = check_ast_validity(deobfuscated_script)

        # Step D: RiskTier evaluation and scoring
        risk_score, risk_tier, risk_reasons = self._calculate_risk(
            raw_script=raw_script,
            deobfuscated_script=deobfuscated_script,
            orig_entropy=orig_entropy,
            entropy_reduction=entropy_reduction,
            carved_urls=carved_urls,
            amsi_findings=amsi_findings,
            policy_findings=policy_findings,
            encoded_layers_count=encoded_layers_count,
            comp_layers_count=comp_layers_count,
            iex_layers_count=iex_layers_count,
        )

        duration_ms = (time.perf_counter() - item_start) * 1000.0

        # Step E: Optional export of deobfuscated script preserving directory structure
        if options.export_deobfuscated and options.output_dir:
            try:
                dest_path = os.path.join(options.output_dir, rel_path)
                os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
                with open(dest_path, "w", encoding="utf-8") as out_f:
                    out_f.write(deobfuscated_script)
            except OSError as io_ex:
                if not error_msg:
                    error_msg = f"Export warning: {io_ex}"

        return FileScanResult(
            file_path=abs_path,
            relative_path=rel_path,
            file_size=file_size,
            sha256=sha256_hash,
            status=scan_status,
            risk_tier=risk_tier,
            risk_score=risk_score,
            risk_reasons=risk_reasons,
            duration_ms=duration_ms,
            encoding_used=encoding_used,
            original_entropy=orig_entropy,
            deobfuscated_entropy=deob_entropy,
            entropy_reduction=entropy_reduction,
            original_length=orig_len,
            deobfuscated_length=deob_len,
            size_reduction_pct=size_reduction_pct,
            original_script=raw_script,
            deobfuscated_script=deobfuscated_script,
            carved_urls=carved_urls,
            amsi_etw_findings=amsi_dicts,
            amsi_etw_count=amsi_count,
            policy_findings=policy_dicts,
            policy_bypass_count=policy_count,
            encoded_command_layers=encoded_layers_count,
            decompressed_stream_layers=comp_layers_count,
            iex_layers=iex_layers_count,
            ast_valid=ast_valid,
            ast_node_count=ast_node_count,
            error_message=error_msg,
        )

    def _calculate_risk(
        self,
        raw_script: str,
        deobfuscated_script: str,
        orig_entropy: float,
        entropy_reduction: float,
        carved_urls: List[str],
        amsi_findings: List[Any],
        policy_findings: List[Any],
        encoded_layers_count: int,
        comp_layers_count: int,
        iex_layers_count: int,
    ) -> Tuple[float, RiskTier, List[str]]:
        """
        Computes composite forensic risk score (0.0 to 100.0), assigns RiskTier,
        and collects structured explanatory finding reasons.
        """
        score = 0.0
        reasons: List[str] = []
        combined_lower = (raw_script + " " + deobfuscated_script).lower()

        # 1. AMSI & ETW Memory Patching / Reflection Tampering (Critical signal)
        if amsi_findings:
            score += 40.0 + min(30.0, (len(amsi_findings) - 1) * 15.0)
            for f in amsi_findings:
                sig_name = getattr(f, "signature_name", None) or getattr(f, "description", "AMSI/ETW Bypass")
                reasons.append(f"AMSI/ETW Defense Evasion: {sig_name}")

        # 2. Native Memory Injection APIs (Critical signal)
        for api in self.MEMORY_INJECTION_APIS:
            if api in combined_lower:
                score += 35.0
                reasons.append(f"Native memory injection / shellcode API: {api}")
                break

        # 3. ExecutionPolicy Bypasses (High signal)
        if policy_findings:
            score += 25.0 + min(20.0, (len(policy_findings) - 1) * 10.0)
            for pf in policy_findings:
                tech = getattr(pf.technique, "value", str(pf.technique)) if hasattr(pf, "technique") else "Bypass"
                reasons.append(f"ExecutionPolicy bypass technique: {tech}")

        # 4. Carved C2 / Remote Payload URLs (High signal)
        if carved_urls:
            score += 30.0 + min(25.0, (len(carved_urls) - 1) * 10.0)
            for url in carved_urls[:3]:
                reasons.append(f"Remote payload download cradle: {url}")
            if len(carved_urls) > 3:
                reasons.append(f"... and {len(carved_urls) - 3} more carved URLs")

        # 5. Nested Base64 Encoded Commands
        if encoded_layers_count > 0:
            score += min(30.0, encoded_layers_count * 20.0)
            reasons.append(f"Recursive Base64 encoded command layer ({encoded_layers_count}x)")

        # 6. In-Memory Compressed Streams (GzipStream / DeflateStream)
        if comp_layers_count > 0:
            score += min(35.0, comp_layers_count * 25.0)
            reasons.append(f"In-memory compressed stream payload ({comp_layers_count}x)")

        # 7. Recursive IEX Execution Wrappers
        if iex_layers_count > 0:
            score += min(25.0, iex_layers_count * 15.0)
            reasons.append(f"Recursive IEX (Invoke-Expression) peeling ({iex_layers_count}x)")

        # 8. High Shannon Entropy (> 5.8 bits/char)
        if orig_entropy > 5.8 and len(raw_script) > 100:
            score += 15.0
            reasons.append(f"High Shannon entropy: {orig_entropy:.2f} bits/char")

        # 9. Significant Entropy Reduction post-deobfuscation
        if entropy_reduction > 1.2:
            score += 10.0
            reasons.append(f"Significant deobfuscation entropy drop: Δ {entropy_reduction:.2f}")

        score = max(0.0, min(100.0, score))

        # Assign Tier
        if score >= 50.0 or any("AMSI/ETW" in r or "memory injection" in r for r in reasons):
            tier = RiskTier.MALICIOUS
        elif score >= 20.0:
            tier = RiskTier.SUSPICIOUS
        else:
            tier = RiskTier.CLEAN

        return round(score, 2), tier, reasons

    def save_report(self, summary: BatchSummary, report_path: str, format_type: str = "text") -> None:
        """Saves formatted batch summary report to destination file."""
        os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
        fmt = format_type.lower()
        if fmt == "json":
            content = summary.to_json(indent=2)
        elif fmt == "markdown":
            content = summary.to_markdown()
        elif fmt == "csv":
            content = summary.to_csv()
        else:
            content = summary.to_text_table()

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(content + "\n")

    def save_iocs(self, summary: BatchSummary, dest_path: str) -> None:
        """Exports carved IoCs to structured JSON destination file."""
        import json
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
        data = summary.export_iocs()
        with open(dest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
