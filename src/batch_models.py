"""
PowerShell AST Batch Forensic Automation & Mass Script Analysis Models.
Defines execution status, risk severity tiers, per-file forensic telemetry schemas,
batch scanning configuration options, and aggregated multi-format summary models.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from typing import Any, Dict, List, Optional


class ScanStatus(str, Enum):
    """Execution status classification of a single script scan."""
    SUCCESS = "success"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    FAILED = "failed"


class RiskTier(str, Enum):
    """Forensic risk and threat severity classification tier."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

    @classmethod
    def from_str(cls, val: Optional[str]) -> "RiskTier":
        """Parses case-insensitive string into RiskTier with fallback to CLEAN."""
        if not val:
            return cls.CLEAN
        norm = str(val).strip().lower()
        for tier in cls:
            if tier.value == norm:
                return tier
        return cls.CLEAN

    @property
    def rank(self) -> int:
        """Numeric ordinal ranking for severity comparisons (0=CLEAN, 1=SUSPICIOUS, 2=MALICIOUS)."""
        ranks = {
            RiskTier.CLEAN: 0,
            RiskTier.SUSPICIOUS: 1,
            RiskTier.MALICIOUS: 2,
        }
        return ranks.get(self, 0)

    def is_at_least(self, min_tier: "RiskTier") -> bool:
        """Returns True if this tier's severity meets or exceeds min_tier."""
        return self.rank >= min_tier.rank


@dataclass
class FileScanResult:
    """Detailed forensic telemetry and deobfuscation metrics for an individual script file."""
    file_path: str
    relative_path: str
    file_size: int = 0
    sha256: str = ""
    status: ScanStatus = ScanStatus.SUCCESS
    risk_tier: RiskTier = RiskTier.CLEAN
    risk_score: float = 0.0
    risk_reasons: List[str] = field(default_factory=list)
    duration_ms: float = 0.0
    encoding_used: Optional[str] = None
    original_entropy: float = 0.0
    deobfuscated_entropy: float = 0.0
    entropy_reduction: float = 0.0
    original_length: int = 0
    deobfuscated_length: int = 0
    size_reduction_pct: float = 0.0
    original_script: Optional[str] = None
    deobfuscated_script: Optional[str] = None
    carved_urls: List[str] = field(default_factory=list)
    amsi_etw_findings: List[Dict[str, Any]] = field(default_factory=list)
    amsi_etw_count: int = 0
    policy_findings: List[Dict[str, Any]] = field(default_factory=list)
    policy_bypass_count: int = 0
    encoded_command_layers: int = 0
    decompressed_stream_layers: int = 0
    iex_layers: int = 0
    ast_valid: bool = True
    ast_node_count: int = 0
    error_message: Optional[str] = None

    def to_dict(self, include_code: bool = False) -> Dict[str, Any]:
        """Serializes result to a clean dictionary."""
        data: Dict[str, Any] = {
            "file_path": self.file_path,
            "relative_path": self.relative_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "status": self.status.value if isinstance(self.status, ScanStatus) else str(self.status),
            "risk_tier": self.risk_tier.value if isinstance(self.risk_tier, RiskTier) else str(self.risk_tier),
            "risk_score": round(self.risk_score, 2),
            "risk_reasons": self.risk_reasons,
            "duration_ms": round(self.duration_ms, 2),
            "encoding_used": self.encoding_used,
            "original_entropy": round(self.original_entropy, 4),
            "deobfuscated_entropy": round(self.deobfuscated_entropy, 4),
            "entropy_reduction": round(self.entropy_reduction, 4),
            "original_length": self.original_length,
            "deobfuscated_length": self.deobfuscated_length,
            "size_reduction_pct": round(self.size_reduction_pct, 2),
            "carved_urls": self.carved_urls,
            "amsi_etw_count": self.amsi_etw_count,
            "amsi_etw_findings": self.amsi_etw_findings,
            "policy_bypass_count": self.policy_bypass_count,
            "policy_findings": self.policy_findings,
            "encoded_command_layers": self.encoded_command_layers,
            "decompressed_stream_layers": self.decompressed_stream_layers,
            "iex_layers": self.iex_layers,
            "ast_valid": self.ast_valid,
            "ast_node_count": self.ast_node_count,
            "error_message": self.error_message,
        }
        if include_code:
            data["original_script"] = self.original_script
            data["deobfuscated_script"] = self.deobfuscated_script
        return data

    def to_json(self, indent: int = 2, ensure_ascii: bool = False, include_code: bool = False) -> str:
        """Serializes result into structured JSON string."""
        return json.dumps(self.to_dict(include_code=include_code), indent=indent, ensure_ascii=ensure_ascii)

    def to_markdown(self) -> str:
        """Renders single file result as markdown summary."""
        lines = [
            f"### `{self.relative_path}` ({self.risk_tier.value.upper()})",
            f"- **Status**: `{self.status.value}`",
            f"- **Risk Score**: {self.risk_score:.1f} / 100",
            f"- **SHA-256**: `{self.sha256}`",
            f"- **Size**: {self.file_size:,} bytes | **Duration**: {self.duration_ms:.1f} ms",
            f"- **Entropy**: {self.original_entropy:.2f} -> {self.deobfuscated_entropy:.2f} (Δ {self.entropy_reduction:+.2f})",
        ]
        if self.risk_reasons:
            lines.append("- **Findings**:")
            for reason in self.risk_reasons:
                lines.append(f"  - {reason}")
        if self.carved_urls:
            lines.append("- **Carved URLs**:")
            for url in self.carved_urls:
                lines.append(f"  - `{url}`")
        if self.error_message:
            lines.append(f"- **Error**: `{self.error_message}`")
        return "\n".join(lines)

    def to_csv(self) -> str:
        """Returns single CSV row representing this file's scan result."""
        reasons_escaped = "; ".join(self.risk_reasons).replace('"', '""')
        urls_escaped = "; ".join(self.carved_urls).replace('"', '""')
        err_escaped = (self.error_message or "").replace('"', '""')
        return (
            f'"{self.relative_path}","{self.status.value}","{self.risk_tier.value}",'
            f'{self.risk_score:.1f},{self.file_size},{self.duration_ms:.1f},'
            f'{self.original_entropy:.2f},{self.deobfuscated_entropy:.2f},'
            f'{self.amsi_etw_count},{self.policy_bypass_count},{len(self.carved_urls)},'
            f'"{self.sha256}","{reasons_escaped}","{urls_escaped}","{err_escaped}"'
        )

    def to_text_table(self) -> str:
        """Returns formatted one-line text record for table display."""
        rel = (self.relative_path[:38] + "..") if len(self.relative_path) > 40 else self.relative_path.ljust(40)
        status_col = self.status.value.upper().ljust(8)
        tier_col = self.risk_tier.value.upper().ljust(10)
        score_col = f"{self.risk_score:5.1f}".rjust(6)
        urls_col = str(len(self.carved_urls)).rjust(4)
        amsi_col = str(self.amsi_etw_count).rjust(5)
        dur_col = f"{self.duration_ms:6.1f}ms".rjust(9)
        return f"{rel} | {status_col} | {tier_col} | {score_col} | {urls_col} | {amsi_col} | {dur_col}"


@dataclass
class BatchScanOptions:
    """Configuration options controlling batch directory scanning and runner behavior."""
    target_dir: str
    output_dir: Optional[str] = None
    max_workers: int = 4
    file_extensions: List[str] = field(default_factory=lambda: [".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".txt"])
    recursive: bool = True
    timeout_sec: float = 30.0
    max_file_size_bytes: int = 10 * 1024 * 1024  # 10 MB limit
    export_deobfuscated: bool = False
    export_iocs: bool = False
    min_risk: RiskTier = RiskTier.CLEAN
    report_format: str = "text"
    report_path: Optional[str] = None
    follow_symlinks: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serializes options to dictionary."""
        return {
            "target_dir": self.target_dir,
            "output_dir": self.output_dir,
            "max_workers": self.max_workers,
            "file_extensions": self.file_extensions,
            "recursive": self.recursive,
            "timeout_sec": self.timeout_sec,
            "max_file_size_bytes": self.max_file_size_bytes,
            "export_deobfuscated": self.export_deobfuscated,
            "export_iocs": self.export_iocs,
            "min_risk": self.min_risk.value if isinstance(self.min_risk, RiskTier) else str(self.min_risk),
            "report_format": self.report_format,
            "report_path": self.report_path,
            "follow_symlinks": self.follow_symlinks,
        }

    def to_json(self, indent: int = 2, ensure_ascii: bool = False) -> str:
        """Serializes options to structured JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=ensure_ascii)


@dataclass
class BatchSummary:
    """Aggregated metrics, health telemetry, and intelligence across a batch scan run."""
    target_dir: str
    total_files_discovered: int = 0
    total_files_scanned: int = 0
    successful_scans: int = 0
    skipped_files: int = 0
    failed_scans: int = 0
    timed_out_scans: int = 0
    clean_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    total_duration_ms: float = 0.0
    total_bytes_scanned: int = 0
    total_urls_carved: int = 0
    unique_urls: List[str] = field(default_factory=list)
    total_amsi_bypasses: int = 0
    total_policy_bypasses: int = 0
    results: List[FileScanResult] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        """Percentage of scanned files that executed successfully without unhandled errors."""
        if self.total_files_scanned == 0:
            return 100.0
        return round((self.successful_scans / self.total_files_scanned) * 100.0, 2)

    @property
    def malicious_rate(self) -> float:
        """Percentage of scanned files classified as MALICIOUS."""
        if self.total_files_scanned == 0:
            return 0.0
        return round((self.malicious_count / self.total_files_scanned) * 100.0, 2)

    @property
    def suspicious_rate(self) -> float:
        """Percentage of scanned files classified as SUSPICIOUS."""
        if self.total_files_scanned == 0:
            return 0.0
        return round((self.suspicious_count / self.total_files_scanned) * 100.0, 2)

    @property
    def average_duration_ms(self) -> float:
        """Average scan latency per file in milliseconds."""
        if self.total_files_scanned == 0:
            return 0.0
        return round(self.total_duration_ms / self.total_files_scanned, 2)

    def to_dict(self, include_code: bool = False) -> Dict[str, Any]:
        """Serializes batch summary to clean dictionary."""
        return {
            "target_dir": self.target_dir,
            "total_files_discovered": self.total_files_discovered,
            "total_files_scanned": self.total_files_scanned,
            "successful_scans": self.successful_scans,
            "skipped_files": self.skipped_files,
            "failed_scans": self.failed_scans,
            "timed_out_scans": self.timed_out_scans,
            "clean_count": self.clean_count,
            "suspicious_count": self.suspicious_count,
            "malicious_count": self.malicious_count,
            "pass_rate": self.pass_rate,
            "malicious_rate": self.malicious_rate,
            "suspicious_rate": self.suspicious_rate,
            "average_duration_ms": self.average_duration_ms,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "total_bytes_scanned": self.total_bytes_scanned,
            "total_urls_carved": self.total_urls_carved,
            "unique_urls_count": len(self.unique_urls),
            "unique_urls": self.unique_urls,
            "total_amsi_bypasses": self.total_amsi_bypasses,
            "total_policy_bypasses": self.total_policy_bypasses,
            "results": [r.to_dict(include_code=include_code) for r in self.results],
        }

    def to_json(self, indent: int = 2, ensure_ascii: bool = False, include_code: bool = False) -> str:
        """Serializes batch summary into structured JSON string."""
        return json.dumps(self.to_dict(include_code=include_code), indent=indent, ensure_ascii=ensure_ascii)

    def to_markdown(self) -> str:
        """Renders comprehensive batch forensic report in GitHub-flavored Markdown."""
        lines = [
            f"# Batch Forensic Scan Report",
            f"",
            f"**Target Directory**: `{self.target_dir}`  ",
            f"**Total Discovered**: `{self.total_files_discovered}` | "
            f"**Scanned**: `{self.total_files_scanned}` | "
            f"**Skipped**: `{self.skipped_files}` | "
            f"**Time**: `{self.total_duration_ms:.1f} ms`",
            f"",
            f"## Threat Severity Distribution",
            f"- 🟢 **Clean**: {self.clean_count} ({100.0 - self.malicious_rate - self.suspicious_rate:.1f}%)",
            f"- 🟡 **Suspicious**: {self.suspicious_count} ({self.suspicious_rate:.1f}%)",
            f"- 🔴 **Malicious**: {self.malicious_count} ({self.malicious_rate:.1f}%)",
            f"- ⚠️ **Failures / Timeouts**: {self.failed_scans} failed, {self.timed_out_scans} timed out",
            f"",
            f"## Threat Intelligence & Forensic Indicators",
            f"- **Total Carved URLs**: `{self.total_urls_carved}` (Unique: `{len(self.unique_urls)}`)",
            f"- **AMSI / ETW Bypass Signatures**: `{self.total_amsi_bypasses}`",
            f"- **ExecutionPolicy Bypass Attempts**: `{self.total_policy_bypasses}`",
            f"- **Total Data Ingested**: `{self.total_bytes_scanned:,}` bytes",
            f"",
        ]

        if self.unique_urls:
            lines.append("### Carved Remote Payload URLs")
            for url in self.unique_urls:
                lines.append(f"- `{url}`")
            lines.append("")

        lines.append("## File Analysis Summary Table")
        lines.append("| File Path | Status | Risk Tier | Score | URLs | AMSI | Time |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in self.results:
            lines.append(
                f"| `{r.relative_path}` | `{r.status.value}` | `{r.risk_tier.value.upper()}` | "
                f"{r.risk_score:.1f} | {len(r.carved_urls)} | {r.amsi_etw_count} | {r.duration_ms:.1f}ms |"
            )

        if any(r.risk_reasons for r in self.results):
            lines.append("")
            lines.append("## Detailed Risk Findings")
            for r in self.results:
                if r.risk_reasons:
                    lines.append(f"### `{r.relative_path}` ({r.risk_tier.value.upper()})")
                    for reason in r.risk_reasons:
                        lines.append(f"- {reason}")

        return "\n".join(lines)

    def to_csv(self) -> str:
        """Exports batch results to standard RFC 4180 CSV string."""
        headers = [
            "RelativePath",
            "Status",
            "RiskTier",
            "RiskScore",
            "FileSizeBytes",
            "DurationMs",
            "OriginalEntropy",
            "DeobfuscatedEntropy",
            "AmsiBypasses",
            "PolicyBypasses",
            "CarvedUrlsCount",
            "SHA256",
            "RiskReasons",
            "CarvedUrls",
            "ErrorMessage",
        ]
        rows = [",".join(f'"{h}"' for h in headers)]
        for r in self.results:
            rows.append(r.to_csv())
        return "\n".join(rows)

    def to_text_table(self) -> str:
        """Renders formatted ASCII table summary of the batch scan results."""
        header = f"{'File Path'.ljust(40)} | {'Status'.ljust(8)} | {'Risk Tier'.ljust(10)} | {'Score'.rjust(6)} | {'URLs'.rjust(4)} | {'AMSI'.rjust(5)} | {'Time'.rjust(9)}"
        separator = "-" * len(header)
        lines = [
            "=" * len(header),
            f" PowerShell AST Batch Forensic Scanner Summary Report",
            f" Target: {self.target_dir}",
            f" Files: {self.total_files_scanned} scanned, {self.clean_count} clean, {self.suspicious_count} suspicious, {self.malicious_count} malicious",
            f" Time: {self.total_duration_ms:.1f} ms | Carved URLs: {self.total_urls_carved} | AMSI: {self.total_amsi_bypasses} | Policy: {self.total_policy_bypasses}",
            "=" * len(header),
            header,
            separator,
        ]
        for r in self.results:
            lines.append(r.to_text_table())
        lines.append(separator)
        lines.append(
            f" TOTAL: {self.total_files_scanned} files | MALICIOUS: {self.malicious_count} | SUSPICIOUS: {self.suspicious_count} | CLEAN: {self.clean_count} | DURATION: {self.total_duration_ms:.1f}ms"
        )
        lines.append("=" * len(header))
        return "\n".join(lines)

    def export_iocs(self) -> Dict[str, Any]:
        """Aggregates all carved URLs, IP targets, and malicious file hashes into an IoC dictionary."""
        all_urls: List[str] = list(self.unique_urls)
        malicious_hashes: List[str] = [
            r.sha256 for r in self.results if r.risk_tier == RiskTier.MALICIOUS and r.sha256
        ]
        suspicious_hashes: List[str] = [
            r.sha256 for r in self.results if r.risk_tier == RiskTier.SUSPICIOUS and r.sha256
        ]
        amsi_signatures_found: List[str] = []
        for r in self.results:
            for finding in r.amsi_etw_findings:
                sig_id = finding.get("signature_id") or finding.get("id")
                if sig_id and sig_id not in amsi_signatures_found:
                    amsi_signatures_found.append(sig_id)

        return {
            "target_dir": self.target_dir,
            "total_iocs": len(all_urls) + len(malicious_hashes) + len(suspicious_hashes),
            "carved_urls": all_urls,
            "malicious_file_hashes_sha256": malicious_hashes,
            "suspicious_file_hashes_sha256": suspicious_hashes,
            "amsi_etw_signature_ids": amsi_signatures_found,
        }
