"""
Command-Line Interface (CLI) for PowerShell AST Deobfuscator.
"""

import argparse
import json
import os
import sys

from .ast_exporter import ASTExporter
from .ast_visualizer import ASTVisualizer
from .benchmark import (
    get_corpus,
    get_corpus_by_category,
    get_sample,
    run_benchmark,
    save_report,
    to_json_report,
    to_markdown_report,
    to_text_report,
)
from .deobfuscator_engine import PowerShellDeobfuscator
from .lexer import PowerShellLexer
from .parser import PowerShellParser
from .webclient_tracer import carve_all_urls, extract_download_urls, trace_webclient


def main() -> None:
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
        help="Extract and print innermost Base64 decoded payload script directly",
    )
    parser.add_argument(
        "--carve-urls",
        action="store_true",
        help="Extract and dump all carved remote payload download targets as structured JSON",
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
        "--benchmark",
        action="store_true",
        help="Execute automated deobfuscation accuracy benchmark across 30-sample corpus",
    )
    parser.add_argument(
        "--benchmark-sample",
        metavar="ID",
        help="Execute benchmark harness for a specific sample ID (e.g., SAMPLE-01)",
    )
    parser.add_argument(
        "--benchmark-category",
        metavar="CATEGORY",
        help="Execute benchmark harness for all samples in a category",
    )
    parser.add_argument(
        "--benchmark-report",
        metavar="PATH",
        help="Destination file path to persist generated benchmark report",
    )
    parser.add_argument(
        "--benchmark-format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format for benchmark report (default: text)",
    )

    args = parser.parse_args()

    # Handle benchmark execution mode
    if args.benchmark or args.benchmark_sample or args.benchmark_category:
        if args.benchmark_sample:
            sample = get_sample(args.benchmark_sample)
            if not sample:
                sys.stderr.write(f"[-] Error: Benchmark sample '{args.benchmark_sample}' not found.\n")
                sys.exit(1)
            target_corpus = [sample]
        elif args.benchmark_category:
            target_corpus = get_corpus_by_category(args.benchmark_category)
            if not target_corpus:
                sys.stderr.write(f"[-] Error: Benchmark category '{args.benchmark_category}' not found or empty.\n")
                sys.exit(1)
        else:
            target_corpus = get_corpus()

        benchmark_summary = run_benchmark(corpus=target_corpus)
        if args.benchmark_format == "json":
            report_content = to_json_report(benchmark_summary)
        elif args.benchmark_format == "markdown":
            report_content = to_markdown_report(benchmark_summary)
        else:
            report_content = to_text_report(benchmark_summary)

        if args.benchmark_report:
            save_report(report_content, args.benchmark_report)
            print(f"[+] Benchmark report ({args.benchmark_format}) saved to: {args.benchmark_report}")
        else:
            print(report_content)
        return

    # Check for missing input argument when not in benchmark mode
    if args.input is None:
        parser.print_help()
        return

    # Determine input content
    if os.path.isfile(args.input):
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            script_text = f.read()
    else:
        script_text = args.input

    # 1. Token dump
    if args.tokens:
        lexer = PowerShellLexer(script_text)
        tokens = lexer.tokenize()
        output_text = "\n".join(str(tok) for tok in tokens)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] Token stream saved to: {args.output}")
        else:
            print(output_text)
        return

    # Determine requested AST format
    export_format = args.format
    if args.mermaid:
        export_format = "mermaid"
    elif args.dot:
        export_format = "dot"
    elif args.json:
        export_format = "json"
    elif args.ascii:
        export_format = "ascii"

    is_ast_mode = args.ast or args.tree or (export_format is not None) or args.stats

    # 2. AST visualization / export / stats
    if is_ast_mode:
        lexer = PowerShellLexer(script_text)
        tokens = lexer.tokenize()
        ps_parser = PowerShellParser(tokens)
        ast = ps_parser.parse()

        if args.stats:
            exporter = ASTExporter()
            metrics = exporter.extract_metrics(ast)
            output_text = json.dumps(metrics, indent=2, ensure_ascii=False)
        elif export_format == "mermaid":
            exporter = ASTExporter()
            output_text = exporter.to_mermaid(ast, wrap_markdown=False)
        elif export_format == "dot":
            exporter = ASTExporter()
            output_text = exporter.to_dot(ast)
        elif export_format == "json":
            exporter = ASTExporter()
            output_text = exporter.to_json(ast, indent=2)
        elif export_format == "ascii":
            visualizer = ASTVisualizer(unicode=False)
            output_text = visualizer.render(ast)
        elif export_format == "raw":
            output_text = str(ast)
        else:
            # Default tree format: clean Unicode tree
            visualizer = ASTVisualizer(unicode=True)
            output_text = visualizer.render(ast)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] AST output saved to: {args.output}")
        else:
            print(output_text)
        return

    # 3. Base64 encoded command forensic layers / payload extraction
    if args.layers or args.extract_b64:
        engine = PowerShellDeobfuscator(
            unwrap_subexpr=args.unwrap_subexpr,
            normalize_casing=args.normalize_casing,
        )
        result = engine.deobfuscate(script_text)
        layers = engine.last_layers
        if args.layers:
            layers_data = [
                {
                    "depth": l.depth,
                    "cli_binary": l.cli_binary,
                    "flags": l.flags,
                    "detected_encoding": l.detected_encoding,
                    "entropy_before": l.entropy_before,
                    "entropy_after": l.entropy_after,
                    "b64_payload_preview": l.b64_payload[:40] + ("..." if len(l.b64_payload) > 40 else ""),
                    "decoded_content": l.decoded_content,
                }
                for l in layers
            ]
            output_text = json.dumps(
                {
                    "total_layers": len(layers),
                    "layers": layers_data,
                    "final_script": result,
                },
                indent=2,
                ensure_ascii=False,
            )
        else:
            # --extract-b64: dump decoded content of innermost layer or deobfuscated result
            output_text = layers[-1].decoded_content if layers else result

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] Output saved to: {args.output}")
        else:
            print(output_text)
        return

    # 4. Remote payload URL carving and WebClient cradle analysis
    if args.carve_urls or args.urls:
        engine = PowerShellDeobfuscator(
            unwrap_subexpr=args.unwrap_subexpr,
            normalize_casing=args.normalize_casing,
        )
        deobf_script = engine.deobfuscate(script_text)
        targets = carve_all_urls(deobf_script)
        raw_targets = carve_all_urls(script_text)
        seen_urls = {t.url for t in targets}
        for rt in raw_targets:
            if rt.url not in seen_urls:
                seen_urls.add(rt.url)
                targets.append(rt)

        if args.urls:
            urls_list = sorted({t.url for t in targets if t.is_valid_url})
            output_text = "\n".join(urls_list)
        else:
            output_text = json.dumps([t.to_dict() for t in targets], indent=2, ensure_ascii=False)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] Carved URLs saved to: {args.output}")
        else:
            print(output_text)
        return

    # 5. IEX wrapper layer forensic telemetry dump
    if args.trace_iex:
        engine = PowerShellDeobfuscator(
            unwrap_subexpr=args.unwrap_subexpr,
            normalize_casing=args.normalize_casing,
            unwrap_iex=True,
        )
        deobf_script = engine.deobfuscate(script_text)
        iex_layers = [l.to_dict() for l in engine.last_iex_layers]
        output_text = json.dumps(
            {
                "total_layers": len(iex_layers),
                "is_peeled": len(iex_layers) > 0,
                "layers": iex_layers,
                "final_script": deobf_script,
            },
            indent=2,
            ensure_ascii=False,
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + "\n")
            print(f"[+] IEX trace saved to: {args.output}")
        else:
            print(output_text)
        return

    # 6. Default: Full deobfuscation engine
    engine = PowerShellDeobfuscator(
        unwrap_subexpr=args.unwrap_subexpr,
        normalize_casing=args.normalize_casing,
        unwrap_iex=args.unwrap_iex,
    )
    result = engine.deobfuscate(script_text)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"[+] Deobfuscated script saved to: {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
