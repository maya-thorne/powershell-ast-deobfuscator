"""
PowerShell Multi-Pass Fixed-Point Deobfuscation Engine.
Iterates AST normalization passes until code convergence is achieved.
"""

import re
from typing import Any, Dict, List, Optional

from .amsi_etw_detector import PowerShellAmsiEtwDetector
from .amsi_etw_signatures import AmsiEtwFinding
from .compression import DecompressedStreamLayer, PowerShellCompressionReducer
from .encoded_command_unwrapper import EncodedCommandLayer, PowerShellEncodedCommandUnwrapper
from .iex_unwrapper import IEXLayer
from .lexer import PowerShellLexer
from .normalizer import PowerShellNormalizer
from .parser import PowerShellParser
from .scope_models import ScopeAnalysisSummary


class PowerShellDeobfuscator:
    """
    Multi-pass deobfuscation engine for obfuscated PowerShell scripts.
    Executes AST normalization, cryptographic unboxing, reflection unwrapping,
    pipeline simplification, recursive Base64 encoded command unraveling,
    recursive in-memory stream decompression (GzipStream / DeflateStream),
    variable scope chain analysis & constant propagation,
    recursive IEX (Invoke-Expression) wrapper peeling, and AMSI/ETW bypass detection.
    """

    MAX_ITERATIONS = 10

    def __init__(
        self,
        symbols: Optional[Dict[str, Any]] = None,
        unwrap_subexpr: bool = True,
        normalize_casing: bool = True,
        unwrap_iex: bool = True,
        decompress_streams: bool = True,
        detect_amsi_etw: bool = True,
        neutralize_amsi_etw: bool = False,
        neutralize_amsi_mode: str = "comment",
        inline_scoped_vars: bool = True,
        eliminate_dead_vars: bool = False,
    ):
        self.symbols = symbols if symbols is not None else {}
        self.unwrap_subexpr = unwrap_subexpr
        self.normalize_casing = normalize_casing
        self.unwrap_iex = unwrap_iex
        self.decompress_streams = decompress_streams
        self.detect_amsi_etw = detect_amsi_etw
        self.neutralize_amsi_etw = neutralize_amsi_etw
        self.neutralize_amsi_mode = neutralize_amsi_mode
        self.inline_scoped_vars = inline_scoped_vars
        self.eliminate_dead_vars = eliminate_dead_vars
        self.encoded_unwrapper = PowerShellEncodedCommandUnwrapper(symbols=self.symbols)
        self.comp_reducer = PowerShellCompressionReducer(symbols=self.symbols)
        self.amsi_detector = PowerShellAmsiEtwDetector(symbols=self.symbols)
        self.last_layers: List[EncodedCommandLayer] = []
        self.last_compression_layers: List[DecompressedStreamLayer] = []
        self.last_iex_layers: List[IEXLayer] = []
        self.last_amsi_etw_findings: List[AmsiEtwFinding] = []
        self.last_scope_summary: Optional[ScopeAnalysisSummary] = None

    def deobfuscate(self, script: str) -> str:
        """
        Executes multi-pass fixed-point deobfuscation loop until code convergence.
        """
        current = script.strip()
        iteration = 0
        self.last_layers = []
        self.last_compression_layers = []
        self.last_iex_layers = []
        self.last_amsi_etw_findings = []
        self.last_scope_summary = None

        while iteration < self.MAX_ITERATIONS:
            iteration += 1
            prev = current

            # Pass 0: Recursive compressed stream unwrapping (GzipStream / DeflateStream)
            if self.decompress_streams:
                comp_res = self.comp_reducer.unwrap_text(current)
                if comp_res.has_decompressed_streams:
                    self.last_compression_layers.extend(comp_res.layers)
                    current = comp_res.unwrapped_script

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
                    decompress_streams=self.decompress_streams,
                    inline_scoped_vars=self.inline_scoped_vars,
                    eliminate_dead_vars=self.eliminate_dead_vars,
                )
                norm_ast = normalizer.normalize(ast)
                if normalizer.comp_reducer.last_layers:
                    self.last_compression_layers.extend(normalizer.comp_reducer.last_layers)
                if normalizer.iex_unwrapper.last_layers:
                    self.last_iex_layers.extend(normalizer.iex_unwrapper.last_layers)
                if normalizer.scope_inliner.last_summary:
                    self.last_scope_summary = normalizer.scope_inliner.last_summary
                current = normalizer.to_source(norm_ast)
            except Exception:
                # If AST parsing fails on partial fragment, retain current representation
                pass

            # Pass 3: Post-regex string join normalization
            current = self._merge_consecutive_quotes(current)

            if current == prev:
                break

        # Pass 4: AMSI & ETW bypass signature detection and optional neutralization
        if self.detect_amsi_etw or self.neutralize_amsi_etw:
            self.last_amsi_etw_findings = self.amsi_detector.detect(current)
            if self.neutralize_amsi_etw and self.last_amsi_etw_findings:
                current = self.amsi_detector.neutralize(
                    current, mode=self.neutralize_amsi_mode
                ).sanitized_script


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

    def generate_yara_rule(
        self,
        script: str,
        options: Optional[Any] = None,
        metadata: Optional[Any] = None,
    ) -> str:
        """
        Deobfuscates script and synthesizes a corresponding YARA 4.x detection rule.
        """
        from .threat_rule_generator import ThreatRuleGenerator

        deobf_script = self.deobfuscate(script)
        generator = ThreatRuleGenerator()
        return generator.generate_yara(
            raw_script=script,
            deobfuscated_script=deobf_script,
            metadata=metadata,
            options=options,
        )

    def generate_sigma_rule(
        self,
        script: str,
        options: Optional[Any] = None,
        metadata: Optional[Any] = None,
    ) -> str:
        """
        Deobfuscates script and synthesizes a corresponding Sigma YAML detection rule.
        """
        from .threat_rule_generator import ThreatRuleGenerator

        deobf_script = self.deobfuscate(script)
        generator = ThreatRuleGenerator()
        return generator.generate_sigma(
            raw_script=script,
            deobfuscated_script=deobf_script,
            metadata=metadata,
            options=options,
        )

    def generate_threat_rules(
        self,
        script: str,
        options: Optional[Any] = None,
        metadata: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Deobfuscates script and synthesizes correlated YARA and Sigma rules with indicator telemetry.
        """
        from .threat_rule_generator import ThreatRuleGenerator

        deobf_script = self.deobfuscate(script)
        generator = ThreatRuleGenerator()
        return generator.generate_ruleset(
            raw_script=script,
            deobfuscated_script=deobf_script,
            metadata=metadata,
            options=options,
        )

    def get_scope_analysis(self, script: str) -> ScopeAnalysisSummary:
        """
        Executes static variable scope and lifecycle analysis over the script AST.
        """
        from .variable_scope import analyze_scopes

        return analyze_scopes(script, symbols=self.symbols)
