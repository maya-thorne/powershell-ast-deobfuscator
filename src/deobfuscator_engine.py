"""
PowerShell Multi-Pass Fixed-Point Deobfuscation Engine.
Iterates AST normalization passes until code convergence is achieved.
"""

import base64
import re
from typing import Dict, Optional

from .lexer import PowerShellLexer
from .normalizer import PowerShellNormalizer
from .parser import PowerShellParser


class PowerShellDeobfuscator:
    """
    Multi-pass deobfuscation engine for obfuscated PowerShell scripts.
    """

    MAX_ITERATIONS = 10

    def __init__(self, symbols: Optional[Dict[str, str]] = None):
        self.symbols = symbols or {}

    def deobfuscate(self, script: str) -> str:
        """
        Executes multi-pass fixed-point deobfuscation loop until code convergence.
        """
        current = script.strip()
        iteration = 0

        while iteration < self.MAX_ITERATIONS:
            iteration += 1
            prev = current

            # Pass 1: Pre-process base64 encoded command arguments (-enc / -EncodedCommand)
            current = self._decode_encoded_commands(current)

            # Pass 2: Lexical scanning & AST normalization
            try:
                lexer = PowerShellLexer(current)
                tokens = lexer.tokenize()
                parser = PowerShellParser(tokens)
                ast = parser.parse()
                normalizer = PowerShellNormalizer(symbols=self.symbols)
                norm_ast = normalizer.normalize(ast)
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
        """Detects -EncodedCommand [Base64] and decodes UTF-16LE payload."""
        pattern = re.compile(
            r"(?:-e|-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{8,})",
            re.IGNORECASE,
        )

        def decode_match(match: re.Match) -> str:
            b64_str = match.group(1)
            try:
                raw_bytes = base64.b64decode(b64_str)
                decoded = raw_bytes.decode("utf-16le", errors="ignore")
                if len(decoded) > 0 and all(ord(c) >= 32 or c in "\r\n\t" for c in decoded):
                    return f"-Command \"{decoded}\""
            except Exception:
                pass
            return match.group(0)

        return pattern.sub(decode_match, text)

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
