"""
Command-Line Interface (CLI) for PowerShell AST Deobfuscator.
"""

import argparse
import os
import sys

from .deobfuscator_engine import PowerShellDeobfuscator
from .lexer import PowerShellLexer
from .parser import PowerShellParser


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="powershell-ast-deobfuscator",
        description="Compiler-Grade AST Parser & Multi-Pass Deobfuscator for Windows PowerShell",
    )
    parser.add_argument("input", help="PowerShell script code string or path to .ps1 file")
    parser.add_argument("-o", "--output", help="Write deobfuscated output to destination file")
    parser.add_argument("--ast", action="store_true", help="Dump parsed AST tree representation")
    parser.add_argument("--tokens", action="store_true", help="Dump lexical token stream")

    args = parser.parse_args()

    # Determine input content
    if os.path.isfile(args.input):
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            script_text = f.read()
    else:
        script_text = args.input

    if args.tokens:
        lexer = PowerShellLexer(script_text)
        tokens = lexer.tokenize()
        for tok in tokens:
            print(tok)
        return

    if args.ast:
        lexer = PowerShellLexer(script_text)
        tokens = lexer.tokenize()
        ps_parser = PowerShellParser(tokens)
        ast = ps_parser.parse()
        print(ast)
        return

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
