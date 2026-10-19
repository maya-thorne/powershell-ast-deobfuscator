"""
PowerShell AST Deobfuscator CLI Argument Parser Specification.
Defines all command-line switches, flags, groups, and help documentation.
"""

import argparse


def build_cli_parser() -> argparse.ArgumentParser:
    """Builds and returns the comprehensive command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="powershell-ast-deobfuscator",
        description="Compiler-Grade AST Parser, Visualizer & Multi-Pass Deobfuscator for Windows PowerShell",
    )
    parser.add_argument("input", nargs="?", default=None, help="PowerShell script code string or path to .ps1 file")
    parser.add_argument("-o", "--output", help="Write output to destination file")
    parser.add_argument("--tokens", action="store_true", help="Dump lexical token stream")
    parser.add_argument(
        "--ast",
        action="store_true",
        help="Visualize or export parsed AST (default: Unicode tree)",
    )
    parser.add_argument(
        "--tree",
        action="store_true",
        help="Alias for --ast (visualize AST hierarchy)",
    )
    parser.add_argument(
        "--format",
        choices=["tree", "ascii", "mermaid", "json", "dot", "raw"],
        default=None,
        help="Output format for AST export (tree, ascii, mermaid, json, dot, raw)",
    )
    parser.add_argument("--mermaid", action="store_true", help="Export AST as Mermaid flowchart")
    parser.add_argument("--dot", action="store_true", help="Export AST as Graphviz DOT graph")
    parser.add_argument("--json", action="store_true", help="Export AST as structured JSON")
    parser.add_argument("--ascii", action="store_true", help="Export AST as plain ASCII tree")
    parser.add_argument("--stats", action="store_true", help="Display AST structural metrics and node counts")
    parser.add_argument(
        "--layers",
        action="store_true",
        help="Dump all recursive Base64 encoded command layers and forensic telemetry (JSON)",
    )
    parser.add_argument(
        "--normalize-casing",
        action="store_true",
        default=True,
        help="Normalize casing of cmdlets, keywords, types, members, and variables (default: True)",
    )
    parser.add_argument(
        "--no-normalize-casing",
        dest="normalize_casing",
        action="store_false",
        help="Disable casing normalization",
    )
    parser.add_argument(
        "--unwrap-subexpr",
        action="store_true",
        default=True,
        help="Unbox redundant subexpressions and expandable strings $(...) (default: True)",
    )
    parser.add_argument(
        "--no-unwrap-subexpr",
        dest="unwrap_subexpr",
        action="store_false",
        help="Disable subexpression unwrapping",
    )
    parser.add_argument(
        "--extract-b64",
        action="store_true",
        help="Extract and dump the final decoded Base64 payload content directly",
    )
    parser.add_argument(
        "--carve-urls",
        action="store_true",
        help="Carve all remote payload URLs and WebClient download endpoints into structured JSON",
    )
    parser.add_argument(
        "--urls",
        action="store_true",
        help="Extract and print unique canonical remote payload URLs (one per line)",
    )
    parser.add_argument(
        "--trace-iex",
        action="store_true",
        help="Extract and dump all recursive IEX (Invoke-Expression) wrapper layers as structured JSON",
    )
    parser.add_argument(
        "--no-unwrap-iex",
        dest="unwrap_iex",
        action="store_false",
        default=True,
        help="Disable automatic IEX wrapper peeling",
    )
    parser.add_argument(
        "--decompress-streams",
        action="store_true",
        default=True,
        help="Decompress in-memory GzipStream, DeflateStream, and BrotliStream payloads (default: True)",
    )
    parser.add_argument(
        "--no-decompress-streams",
        dest="decompress_streams",
        action="store_false",
        help="Disable in-memory compressed stream deobfuscation",
    )
    parser.add_argument(
        "--trace-streams",
        action="store_true",
        help="Extract and dump in-memory compressed stream layer telemetry as structured JSON",
    )
    parser.add_argument(
        "--scope-analysis",
        action="store_true",
        help="Perform variable scope chain and lifecycle analysis, outputting human-readable report",
    )
    parser.add_argument(
        "--scope-json",
        action="store_true",
        help="Dump variable scope hierarchy and symbol tables as structured JSON",
    )
    parser.add_argument(
        "--export-scope-json",
        metavar="PATH",
        help="Export structured variable scope analysis to a JSON destination file",
    )
    parser.add_argument(
        "--no-inline-vars",
        dest="inline_scoped_vars",
        action="store_false",
        default=True,
        help="Disable automatic scoped constant variable inlining",
    )
    parser.add_argument(
        "--eliminate-dead-vars",
        action="store_true",
        default=False,
        help="Eliminate dead variable assignments that have zero side-effects",
    )
    parser.add_argument(
        "--detect-amsi",
        action="store_true",
        help="Detect AMSI and ETW bypass signatures and dump findings as structured JSON",
    )
    parser.add_argument(
        "--neutralize-amsi",
        action="store_true",
        help="Neutralize and sanitize detected AMSI and ETW bypass code blocks",
    )
    parser.add_argument(
        "--neutralize-mode",
        choices=["comment", "strip", "invert"],
        default="comment",
        help="Sanitization mode for --neutralize-amsi: comment (default), strip, or invert",
    )
    parser.add_argument(
        "--amsi-signatures",
        action="store_true",
        help="Dump all registered AMSI and ETW bypass detection signatures as structured JSON",
    )

    # Runtime ExecutionPolicy Simulation & Neutralization Options
    parser.add_argument(
        "--policy-analysis",
        action="store_true",
        help="Simulate runtime ExecutionPolicy state machine across 5 scopes and print forensic report",
    )
    parser.add_argument(
        "--policy-json",
        action="store_true",
        help="Dump runtime ExecutionPolicy simulation findings, transitions, and matrix as structured JSON",
    )
    parser.add_argument(
        "--export-policy-json",
        metavar="PATH",
        help="Export structured ExecutionPolicy simulation telemetry to a JSON destination file",
    )
    parser.add_argument(
        "--baseline-policy",
        default="Restricted",
        choices=["Restricted", "AllSigned", "RemoteSigned", "Unrestricted", "Bypass"],
        help="Initial default execution policy to simulate against (default: Restricted)",
    )
    parser.add_argument(
        "--machine-policy",
        default=None,
        choices=["Restricted", "AllSigned", "RemoteSigned", "Unrestricted", "Bypass"],
        help="Simulate active Group Policy Computer Configuration (MachinePolicy)",
    )
    parser.add_argument(
        "--neutralize-policy",
        action="store_true",
        help="Neutralize and sanitize detected execution policy bypass statements",
    )
    parser.add_argument(
        "--neutralize-policy-mode",
        choices=["comment", "strip", "invert"],
        default="comment",
        help="Sanitization mode for --neutralize-policy: comment (default), strip, or invert",
    )
    parser.add_argument(
        "--cli-eval",
        metavar="COMMAND",
        default=None,
        help="Evaluate PowerShell command-line launch string for execution policy bypass flags",
    )

    # Benchmark Harness Options
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run comprehensive benchmark suite across all 30 corpus samples",
    )
    parser.add_argument(
        "--benchmark-sample",
        metavar="NAME",
        default=None,
        help="Run benchmark against a specific sample name (e.g. sample_01_backtick_casing)",
    )
    parser.add_argument(
        "--benchmark-category",
        metavar="CATEGORY",
        default=None,
        help="Run benchmark against all samples in a category (e.g. amsi_bypass, string_concatenation)",
    )
    parser.add_argument(
        "--benchmark-format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format for benchmark report (default: text)",
    )
    parser.add_argument(
        "--benchmark-report",
        metavar="PATH",
        default=None,
        help="Destination file path to save benchmark report",
    )

    # Threat Hunting Rule Synthesis Options (YARA & Sigma)
    parser.add_argument(
        "--generate-yara",
        action="store_true",
        help="Synthesize and output a YARA 4.x detection rule for the script payload",
    )
    parser.add_argument(
        "--generate-sigma",
        action="store_true",
        help="Synthesize and output a Sigma YAML detection rule for the script payload",
    )
    parser.add_argument(
        "--generate-rules",
        action="store_true",
        help="Synthesize both YARA and Sigma threat hunting rules and dump telemetry JSON",
    )
    parser.add_argument(
        "--rule-name",
        default=None,
        help="Custom rule name identifier for generated YARA/Sigma detection rules",
    )
    parser.add_argument(
        "--rule-title",
        default=None,
        help="Custom rule title for generated Sigma detection rules",
    )
    parser.add_argument(
        "--rule-target",
        choices=["deobfuscated", "raw", "dual"],
        default="deobfuscated",
        help="Target scope for rule synthesis: deobfuscated (default), raw, or dual",
    )
    parser.add_argument(
        "--sigma-logsource",
        choices=["scriptblock", "process_creation", "module"],
        default="scriptblock",
        help="Sigma logsource target: scriptblock (default, EID 4104), process_creation (EID 4688), or module (EID 4103)",
    )
    parser.add_argument(
        "--yara-condition",
        choices=["balanced", "strict", "loose", "categorized"],
        default="balanced",
        help="YARA condition synthesis style: balanced (default), strict, loose, or categorized",
    )
    parser.add_argument(
        "--rule-output-dir",
        default=None,
        help="Destination directory to save generated .yar and .yml rule files",
    )

    # Regression Stress Fuzzing Harness Options
    parser.add_argument(
        "--fuzz",
        action="store_true",
        help="Run regression stress fuzzing harness across randomized mutation test cases",
    )
    parser.add_argument(
        "--fuzz-iterations",
        type=int,
        default=50,
        metavar="N",
        help="Number of fuzzing test iterations to execute (default: 50)",
    )
    parser.add_argument(
        "--fuzz-seed",
        type=int,
        default=42,
        metavar="SEED",
        help="Random seed for deterministic fuzzing reproducibility (default: 42)",
    )
    parser.add_argument(
        "--fuzz-strategy",
        default=None,
        metavar="STRATEGY",
        help="Specific mutation strategy to test (e.g. backtick_injection, nesting_stress, syntax_corruption)",
    )
    parser.add_argument(
        "--fuzz-format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format for fuzzing report (default: text)",
    )
    parser.add_argument(
        "--fuzz-report",
        default=None,
        metavar="PATH",
        help="Destination file path to save fuzzing harness report",
    )
    parser.add_argument(
        "--fuzz-no-shrink",
        dest="fuzz_shrink",
        action="store_false",
        default=True,
        help="Disable delta-debugging crash reproducer shrinking",
    )

    # Batch Forensic Automation & Mass Script Scanning
    parser.add_argument(
        "--batch",
        "--scan-dir",
        dest="batch_dir",
        metavar="DIR",
        default=None,
        help="Batch scan and analyze all PowerShell scripts in the specified directory",
    )
    parser.add_argument(
        "--batch-output",
        metavar="DIR",
        default=None,
        help="Output directory to export deobfuscated scripts and artifacts preserving directory structure",
    )
    parser.add_argument(
        "--batch-workers",
        type=int,
        default=4,
        metavar="N",
        help="Number of concurrent worker threads for parallel scanning (default: 4)",
    )
    parser.add_argument(
        "--batch-exts",
        default=".ps1,.psm1,.psd1,.bat,.cmd,.txt",
        metavar="EXTS",
        help="Comma-separated file extensions to scan (default: .ps1,.psm1,.psd1,.bat,.cmd,.txt)",
    )
    parser.add_argument(
        "--batch-recursive",
        action="store_true",
        default=True,
        help="Recursively scan subdirectories (default: True)",
    )
    parser.add_argument(
        "--no-batch-recursive",
        dest="batch_recursive",
        action="store_false",
        help="Disable recursive scanning (scan target directory only)",
    )
    parser.add_argument(
        "--batch-format",
        choices=["text", "json", "markdown", "csv"],
        default="text",
        help="Output format for batch report (default: text)",
    )
    parser.add_argument(
        "--batch-report",
        metavar="PATH",
        default=None,
        help="Destination file path to save the batch scan report",
    )
    parser.add_argument(
        "--batch-timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="Per-script deobfuscation timeout in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--batch-export-iocs",
        action="store_true",
        default=False,
        help="Export all extracted IoCs (URLs, C2 endpoints, AMSI hashes) as structured JSON",
    )
    parser.add_argument(
        "--batch-min-risk",
        choices=["clean", "suspicious", "malicious"],
        default="clean",
        help="Minimum risk tier to include in report/export: clean (default), suspicious, malicious",
    )

    return parser
