"""
Compiler-Grade YARA Rule Synthesizer for PowerShell Malware & Threat Hunting.
Generates compliant, high-fidelity YARA 4.x rules with category-prefixed strings,
proper ASCII/WIDE/NOCASE modifiers, hex bytecode patterns, and robust condition trees.
"""

import hashlib
import re
from typing import Dict, List, Optional, Set, Tuple

from .rule_models import IndicatorCategory, RuleMetadata, RuleSeverity, RuleSynthesisOptions, ThreatIndicator


class YaraRuleGenerator:
    """
    Automated YARA rule synthesizer for deobfuscated PowerShell payloads and forensic artifacts.
    """

    PREFIX_MAP: Dict[IndicatorCategory, str] = {
        IndicatorCategory.NETWORK_C2: "c2",
        IndicatorCategory.DEFENSE_EVASION: "evas",
        IndicatorCategory.EXECUTION_CRADLE: "cradle",
        IndicatorCategory.MEMORY_INJECTION: "mem",
        IndicatorCategory.PERSISTENCE: "persist",
        IndicatorCategory.CRYPTO_OBFUSCATION: "crypto",
        IndicatorCategory.SUSPICIOUS_API: "api",
        IndicatorCategory.TARGET_IDENTIFIER: "target",
    }

    def __init__(self) -> None:
        pass

    def generate_rule(
        self,
        indicators: List[ThreatIndicator],
        metadata: Optional[RuleMetadata] = None,
        options: Optional[RuleSynthesisOptions] = None,
    ) -> str:
        """
        Synthesizes a complete, syntactically valid YARA rule from extracted indicators.
        """
        opts = options or RuleSynthesisOptions()
        meta = metadata or self._create_default_metadata(indicators, opts)

        # 1. Clean rule identifier
        clean_rule_name = self._sanitize_identifier(meta.rule_name)

        # 2. Build meta section
        meta_lines = self._build_meta_section(meta)

        # 3. Build strings section
        string_lines, string_categories = self._build_strings_section(indicators, opts)

        # 4. Build condition section
        condition_lines = self._build_condition_section(string_categories, opts)

        # 5. Assemble final rule
        rule_parts = [
            f"rule {clean_rule_name}",
            "{",
            "    meta:",
            *meta_lines,
            "",
            "    strings:",
            *string_lines,
            "",
            "    condition:",
            *condition_lines,
            "}",
            "",
        ]

        return "\n".join(rule_parts)

    def validate_syntax(self, yara_text: str) -> Tuple[bool, List[str]]:
        """
        Performs static linting and verification on generated YARA rule text.
        Returns (is_valid, error_list).
        """
        errors: List[str] = []

        if not re.search(r"\brule\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\{", yara_text):
            errors.append("Missing valid rule declaration header")

        if "meta:" not in yara_text:
            errors.append("Missing 'meta:' section")

        if "strings:" not in yara_text:
            errors.append("Missing 'strings:' section")

        if "condition:" not in yara_text:
            errors.append("Missing 'condition:' section")

        # Check brace balance
        open_braces = yara_text.count("{")
        close_braces = yara_text.count("}")
        if open_braces != close_braces:
            errors.append(f"Mismatched braces: {open_braces} open vs {close_braces} close")

        # Extract defined strings ($id)
        defined_strings = set(re.findall(r"(\$[a-zA-Z0-9_]+)\s*=", yara_text))
        if not defined_strings:
            errors.append("Strings section contains zero string identifiers")

        return (len(errors) == 0, errors)

    def _create_default_metadata(
        self,
        indicators: List[ThreatIndicator],
        options: RuleSynthesisOptions,
    ) -> RuleMetadata:
        """Constructs default rule metadata inferred from indicators."""
        highest_weight = max([ind.weight for ind in indicators], default=5.0)
        severity = RuleSeverity.HIGH
        if highest_weight >= 9.0:
            severity = RuleSeverity.CRITICAL
        elif highest_weight < 6.0:
            severity = RuleSeverity.MEDIUM

        all_techniques: Set[str] = set()
        for ind in indicators:
            all_techniques.update(ind.mitre_techniques)

        return RuleMetadata(
            rule_name="PowerShell_Threat_Payload_Detected",
            title="Auto-Generated PowerShell Threat Detection Rule",
            description="Detects deobfuscated malicious PowerShell activity, network cradles, and evasion hooks.",
            author=options.custom_author or "PowerShell AST Threat Hunter",
            version="1.0.0",
            severity=severity,
            mitre_attack_ids=sorted(list(all_techniques)),
        )

    def _sanitize_identifier(self, name: str) -> str:
        """Sanitizes rule and variable identifiers to meet YARA grammar ([a-zA-Z_][a-zA-Z0-9_]*)."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name.strip())
        if not clean or clean[0].isdigit():
            clean = f"ps_{clean}"
        return clean

    def _build_meta_section(self, meta: RuleMetadata) -> List[str]:
        """Constructs formatted YARA meta lines."""
        lines = [
            f'        description = "{self._escape_yara_string(meta.description)}"',
            f'        author = "{self._escape_yara_string(meta.author)}"',
            f'        date = "{meta.date}"',
            f'        threat_level = "{meta.severity.value}"',
            f'        rule_version = "{meta.version}"',
        ]

        if meta.payload_sha256:
            lines.append(f'        hash = "{meta.payload_sha256}"')

        if meta.mitre_attack_ids:
            mitre_str = ", ".join(meta.mitre_attack_ids)
            lines.append(f'        mitre_technique = "{mitre_str}"')

        for i, ref in enumerate(meta.references):
            lines.append(f'        reference_{i+1} = "{self._escape_yara_string(ref)}"')

        return lines

    def _build_strings_section(
        self,
        indicators: List[ThreatIndicator],
        options: RuleSynthesisOptions,
    ) -> Tuple[List[str], Dict[str, List[str]]]:
        """
        Formats and categorizes string declarations with appropriate YARA modifiers.
        """
        lines: List[str] = []
        string_categories: Dict[str, List[str]] = {}

        # Counter per prefix to ensure unique identifiers
        prefix_counters: Dict[str, int] = {}

        # If zero indicators were extracted, produce a safe generic PowerShell fallback string
        if not indicators:
            fallback_id = "$ps_cradle = \"DownloadString\" ascii wide nocase"
            lines.append(f"        {fallback_id}")
            string_categories["cradle"] = ["$ps_cradle"]
            return lines, string_categories

        for ind in indicators:
            prefix = self.PREFIX_MAP.get(ind.category, "str")
            if options.target_scope == "dual":
                sub_prefix = "deobf" if ind.is_deobfuscated_only else "raw"
                prefix = f"{sub_prefix}_{prefix}"

            count = prefix_counters.get(prefix, 0) + 1
            prefix_counters[prefix] = count
            string_id = f"${prefix}_{count}"

            if prefix not in string_categories:
                string_categories[prefix] = []
            string_categories[prefix].append(string_id)

            # Build modifiers string (ascii, wide, nocase)
            modifiers: List[str] = []
            if options.yara_ascii:
                modifiers.append("ascii")
            if options.yara_wide:
                modifiers.append("wide")
            if options.yara_nocase:
                modifiers.append("nocase")
            mod_str = " ".join(modifiers)

            if ind.indicator_type == "hex":
                # Hex byte pattern
                clean_hex = ind.value.strip()
                lines.append(f"        {string_id} = {{ {clean_hex} }}")
            else:
                # Text string with modifiers
                escaped_val = self._escape_yara_string(ind.value)
                lines.append(f'        {string_id} = "{escaped_val}" {mod_str}')

        return lines, string_categories

    def _build_condition_section(
        self,
        string_categories: Dict[str, List[str]],
        options: RuleSynthesisOptions,
    ) -> List[str]:
        """
        Constructs boolean condition logic based on synthesis options and indicator categories.
        """
        lines: List[str] = []
        all_strings: List[str] = []
        for ids in string_categories.values():
            all_strings.extend(ids)

        # Collect prefixes that have at least one string
        has_c2 = any(p.endswith("c2") for p in string_categories)
        has_evas = any(p.endswith("evas") for p in string_categories)
        has_cradle = any(p.endswith("cradle") for p in string_categories)
        has_mem = any(p.endswith("mem") for p in string_categories)

        filesize_prefix = f"filesize < {options.filesize_limit} and " if options.filesize_limit else ""

        if options.yara_condition_style == "strict":
            # Must match all defined strings
            lines.append(f"        {filesize_prefix}all of them")
            return lines

        if options.yara_condition_style == "loose":
            # Match any single defined string
            lines.append(f"        {filesize_prefix}1 of them")
            return lines

        if options.yara_condition_style == "categorized":
            # Requires correlation across at least 2 distinct functional categories
            sub_clauses: List[str] = []
            for prefix in sorted(string_categories.keys()):
                sub_clauses.append(f"1 of (${prefix}*)")

            if len(sub_clauses) >= 2:
                joined = " and ".join(sub_clauses[:2])
                lines.append(f"        {filesize_prefix}({joined})")
                return lines

        # Default: "balanced" style
        # If high-fidelity C2 target exists: 1 of C2 or (evasion and cradle) or N of them
        clauses: List[str] = []

        if has_c2:
            clauses.append("any of ($*c2*)")

        if has_evas and has_cradle:
            clauses.append("(1 of ($*evas*) and 1 of ($*cradle*))")
        elif has_evas and has_mem:
            clauses.append("(1 of ($*evas*) and 1 of ($*mem*))")

        # Threshold match for general indicators
        count = len(all_strings)
        threshold = min(3, count) if count > 1 else 1
        clauses.append(f"{threshold} of them")

        condition_expr = " or\n        ".join(clauses)
        if len(clauses) > 1:
            lines.append(f"        {filesize_prefix}(")
            lines.append(f"            {condition_expr}")
            lines.append("        )")
        else:
            lines.append(f"        {filesize_prefix}{condition_expr}")

        return lines

    def _escape_yara_string(self, text: str) -> str:
        """
        Escapes backslashes, double quotes, and control characters for YARA text string literals.
        """
        res: List[str] = []
        for ch in text:
            if ch == "\\":
                res.append("\\\\")
            elif ch == '"':
                res.append('\\"')
            elif ch == "\t":
                res.append("\\t")
            elif ch == "\r":
                res.append("\\r")
            elif ch == "\n":
                res.append("\\n")
            elif 32 <= ord(ch) <= 126:
                res.append(ch)
            else:
                res.append(f"\\x{ord(ch):02x}")
        return "".join(res)
