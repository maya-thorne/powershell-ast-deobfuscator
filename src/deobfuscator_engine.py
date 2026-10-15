"""
PowerShell Multi-Pass Fixed-Point Deobfuscation Engine.
Iterates AST normalization passes until code convergence is achieved.
"""

import re
from typing import Any, Dict, List, Optional

from .encoded_command_unwrapper import EncodedCommandLayer, PowerShellEncodedCommandUnwrapper
from .iex_unwrapper import IEXLayer
from .lexer import PowerShellLexer
from .normalizer import PowerShellNormalizer
from .parser import PowerShellParser


class PowerShellDeobfuscator:
    """
    Multi-pass deobfuscation engine for obfuscated PowerShell scripts.
    Executes AST normalization, cryptographic unboxing, reflection unwrapping,
    pipeline simplification, recursive Base64 encoded command unraveling,
    and recursive IEX (Invoke-Expression) wrapper peeling.
    """

    MAX_ITERATIONS = 10

    def __init__(
        self,
        symbols: Optional[Dict[str, Any]] = None,
        unwrap_subexpr: bool = True,
        normalize_casing: bool = True,
        unwrap_iex: bool = True,
    ):
        self.symbols = symbols if symbols is not None else {}
        self.unwrap_subexpr = unwrap_subexpr
        self.normalize_casing = normalize_casing
        self.unwrap_iex = unwrap_iex
        self.encoded_unwrapper = PowerShellEncodedCommandUnwrapper(symbols=self.symbols)
        self.last_layers: List[EncodedCommandLayer] = []
        self.last_iex_layers: List[IEXLayer] = []

    def deobfuscate(self, script: str) -> str:
        """
        Executes multi-pass fixed-point deobfuscation loop until code convergence.
        """
        current = script.strip()
        iteration = 0
        self.last_layers = []
        self.last_iex_layers = []

        while iteration < self.MAX_ITERATIONS:
            iteration += 1
            prev = current

            # Pass 1: Recursive base64 encoded command unwrapping (-enc / -EncodedCommand)
            unwrap_res = self.encoded_unwrapper.unwrap_text(current)
            if unwrap_res.has_encoded_commands:
                self.last_layers.extend(unwrap_res.layers)
                current = unwrap_res.unwrapped_script

            # Pass 2: Lexical scanning & AST normalization
            try:
                lexer = PowerShellLexer(current)
                tokens = lexer.tokenize()
                parser = PowerShellParser(tokens)
                ast = parser.parse()
                normalizer = PowerShellNormalizer(
                    symbols=self.symbols,
                    unwrap_subexpr=self.unwrap_subexpr,
                    normalize_casing=self.normalize_casing,
                    unwrap_iex=self.unwrap_iex,
                )
                norm_ast = normalizer.normalize(ast)
                if normalizer.iex_unwrapper.last_layers:
                    self.last_iex_layers.extend(normalizer.iex_unwrapper.last_layers)
                current = normalizer.to_source(norm_ast)
            except Exception:
                # If AST parsing fails on partial fragment, retain current representation
                pass

            # Pass 3: Post-regex string join normalization
            current = self._merge_consecutive_quotes(current)

            if current == prev:
                break

        return current

    def _decode_encoded_commands(self, text: str) -> str:
        """Backward-compatible proxy delegating to recursive encoded command unwrapper."""
        return self.encoded_unwrapper.unwrap_text(text).unwrapped_script

    def _merge_consecutive_quotes(self, text: str) -> str:
        """Folds remaining simple adjacent literal joins ('a'+'b')."""
        pattern = re.compile(r"'([^'\r\n]+)'\s*\+\s*'([^'\r\n]+)'")
        prev = text
        while True:
            text = pattern.sub(r"'\1\2'", text)
            if text == prev:
                break
            prev = text
        return text
