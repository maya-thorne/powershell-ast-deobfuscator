"""
Command-Line Interface (CLI) for PowerShell AST Deobfuscator.
"""

import argparse
import json
import os
import sys

from .ast_exporter import ASTExporter
from .ast_visualizer import ASTVisualizer
from .deobfuscator_engine import PowerShellDeobfuscator
from .lexer import PowerShellLexer
from .parser import PowerShellParser


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="powershell-ast-deobfuscator",
        description="Compiler-Grade AST Parser, Visualizer & Multi-Pass Deobfuscator for Windows PowerShell",
    )
    parser.add_argument("input", help="PowerShell script code string or path to .ps1 file")
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

    args = parser.parse_args()

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

    # 3. Default: Full deobfuscation engine
    engine = PowerShellDeobfuscator()
    result = engine.deobfuscate(script_text)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"[+] Deobfuscated script saved to: {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
