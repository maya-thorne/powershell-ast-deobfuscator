"""
Unified Facade for YARA and Sigma Threat Hunting Rule Generation.
Orchestrates indicator extraction, YARA 4.x rule synthesis, and SigmaHQ YAML generation
with direct integration into the PowerShell AST deobfuscation pipeline.
"""

import hashlib
import os
from typing import Any, Dict, List, Optional, Tuple

from .indicator_extractor import PowerShellIndicatorExtractor
from .rule_models import (
    IndicatorCategory,
    RuleMetadata,
    RuleSeverity,
    RuleStatus,
    RuleSynthesisOptions,
    ThreatIndicator,
)
from .sigma_generator import SigmaRuleGenerator
from .yara_generator import YaraRuleGenerator


class ThreatRuleGenerator:
    """
    High-level threat hunting rule generator producing correlated YARA and Sigma signatures.
    """

    def __init__(self) -> None:
        self.extractor = PowerShellIndicatorExtractor()
        self.yara_gen = YaraRuleGenerator()
        self.sigma_gen = SigmaRuleGenerator()

    def extract_indicators(
        self,
        raw_script: str,
        deobfuscated_script: Optional[str] = None,
        options: Optional[RuleSynthesisOptions] = None,
    ) -> List[ThreatIndicator]:
        """Extracts and scores forensic indicators across raw and deobfuscated scripts."""
        return self.extractor.extract_indicators(
            raw_script=raw_script,
            deobfuscated_script=deobfuscated_script,
            options=options,
        )

    def generate_yara(
        self,
        raw_script: str,
        deobfuscated_script: Optional[str] = None,
        metadata: Optional[RuleMetadata] = None,
        options: Optional[RuleSynthesisOptions] = None,
    ) -> str:
        """Generates a complete YARA rule from extracted PowerShell indicators."""
        opts = options or RuleSynthesisOptions()
        indicators = self.extract_indicators(raw_script, deobfuscated_script, opts)
        meta = metadata or self._infer_metadata(raw_script, deobfuscated_script, indicators, opts)
        return self.yara_gen.generate_rule(indicators, metadata=meta, options=opts)

    def generate_sigma(
        self,
        raw_script: str,
        deobfuscated_script: Optional[str] = None,
        metadata: Optional[RuleMetadata] = None,
        options: Optional[RuleSynthesisOptions] = None,
    ) -> str:
        """Generates a complete Sigma YAML rule from extracted PowerShell indicators."""
        opts = options or RuleSynthesisOptions()
        indicators = self.extract_indicators(raw_script, deobfuscated_script, opts)
        meta = metadata or self._infer_metadata(raw_script, deobfuscated_script, indicators, opts)
        return self.sigma_gen.generate_rule(indicators, metadata=meta, options=opts)

    def generate_ruleset(
        self,
        raw_script: str,
        deobfuscated_script: Optional[str] = None,
        metadata: Optional[RuleMetadata] = None,
        options: Optional[RuleSynthesisOptions] = None,
    ) -> Dict[str, Any]:
        """
        Synthesizes both YARA and Sigma detection rules along with complete indicator telemetry.
        """
        opts = options or RuleSynthesisOptions()
        indicators = self.extract_indicators(raw_script, deobfuscated_script, opts)
        meta = metadata or self._infer_metadata(raw_script, deobfuscated_script, indicators, opts)

        yara_text = self.yara_gen.generate_rule(indicators, metadata=meta, options=opts)
        sigma_text = self.sigma_gen.generate_rule(indicators, metadata=meta, options=opts)

        category_counts: Dict[str, int] = {}
        all_mitre: List[str] = []
        for ind in indicators:
            cat_name = ind.category.value if isinstance(ind.category, IndicatorCategory) else str(ind.category)
            category_counts[cat_name] = category_counts.get(cat_name, 0) + 1
            for m in ind.mitre_techniques:
                if m not in all_mitre:
                    all_mitre.append(m)

        summary = {
            "total_indicators": len(indicators),
            "category_distribution": category_counts,
            "severity": meta.severity.value,
            "mitre_techniques": sorted(all_mitre),
            "payload_sha256": meta.payload_sha256,
        }

        return {
            "yara": yara_text,
            "sigma": sigma_text,
            "indicators": [ind.to_dict() for ind in indicators],
            "metadata": meta.to_dict(),
            "summary": summary,
        }

    def save_rules(
        self,
        ruleset: Dict[str, Any],
        output_dir: str,
        base_name: str = "powershell_threat",
    ) -> Dict[str, str]:
        """
        Persists synthesized YARA and Sigma rules into destination directory.
        Returns paths to created files.
        """
        os.makedirs(output_dir, exist_ok=True)
        yara_path = os.path.join(output_dir, f"{base_name}.yar")
        sigma_path = os.path.join(output_dir, f"{base_name}.yml")

        with open(yara_path, "w", encoding="utf-8") as f:
            f.write(ruleset["yara"])

        with open(sigma_path, "w", encoding="utf-8") as f:
            f.write(ruleset["sigma"])

        return {
            "yara": yara_path,
            "sigma": sigma_path,
        }

    def _infer_metadata(
        self,
        raw_script: str,
        deobfuscated_script: Optional[str],
        indicators: List[ThreatIndicator],
        options: RuleSynthesisOptions,
    ) -> RuleMetadata:
        """Derives rule name, severity, and payload hash from analysis context."""
        target_text = deobfuscated_script if deobfuscated_script is not None else raw_script
        sha256_hash = hashlib.sha256(target_text.encode("utf-8")).hexdigest()

        highest_weight = max([ind.weight for ind in indicators], default=5.0)
        if highest_weight >= 9.0:
            severity = RuleSeverity.CRITICAL
        elif highest_weight >= 7.0:
            severity = RuleSeverity.HIGH
        elif highest_weight >= 5.0:
            severity = RuleSeverity.MEDIUM
        else:
            severity = RuleSeverity.LOW

        all_mitre: List[str] = []
        for ind in indicators:
            for m in ind.mitre_techniques:
                if m not in all_mitre:
                    all_mitre.append(m)

        rule_name = f"PowerShell_Hunt_{sha256_hash[:8]}"

        return RuleMetadata(
            rule_name=rule_name,
            title=f"Suspicious PowerShell Threat Activity [{sha256_hash[:8]}]",
            description="Auto-synthesized YARA/Sigma hunting rule targeting deobfuscated PowerShell payload.",
            author=options.custom_author or "PowerShell AST Threat Hunter",
            severity=severity,
            mitre_attack_ids=sorted(all_mitre),
            payload_sha256=sha256_hash,
        )


# Functional convenience interfaces
def generate_yara_rule(
    raw_script: str,
    deobfuscated_script: Optional[str] = None,
    metadata: Optional[RuleMetadata] = None,
    options: Optional[RuleSynthesisOptions] = None,
) -> str:
    """Convenience functional interface to generate a YARA rule."""
    generator = ThreatRuleGenerator()
    return generator.generate_yara(raw_script, deobfuscated_script, metadata, options)


def generate_sigma_rule(
    raw_script: str,
    deobfuscated_script: Optional[str] = None,
    metadata: Optional[RuleMetadata] = None,
    options: Optional[RuleSynthesisOptions] = None,
) -> str:
    """Convenience functional interface to generate a Sigma YAML rule."""
    generator = ThreatRuleGenerator()
    return generator.generate_sigma(raw_script, deobfuscated_script, metadata, options)


def generate_threat_rules(
    raw_script: str,
    deobfuscated_script: Optional[str] = None,
    metadata: Optional[RuleMetadata] = None,
    options: Optional[RuleSynthesisOptions] = None,
) -> Dict[str, Any]:
    """Convenience functional interface to generate full YARA/Sigma hunting ruleset."""
    generator = ThreatRuleGenerator()
    return generator.generate_ruleset(raw_script, deobfuscated_script, metadata, options)
