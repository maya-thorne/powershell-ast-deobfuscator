"""
Compiler-Grade Sigma Rule Synthesizer for PowerShell SIEM/EDR Threat Hunting.
Generates compliant SigmaHQ rules targeting PowerShell ScriptBlock Logging (EID 4104),
Module Logging (EID 4103), and Process Creation (EID 4688 / Sysmon 1) with pure-Python YAML formatting.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from .rule_models import (
    IndicatorCategory,
    MitreAttackCatalog,
    RuleMetadata,
    RuleSeverity,
    RuleSynthesisOptions,
    ThreatIndicator,
)


class SigmaRuleGenerator:
    """
    Automated Sigma rule generator producing standardized YAML detection signatures.
    """

    LOGSOURCE_CONFIGS: Dict[str, Dict[str, Any]] = {
        "scriptblock": {
            "product": "windows",
            "service": "powershell",
            "definition": "Requirements: ScriptBlock Logging (Event ID 4104) enabled",
            "field": "ScriptBlockText",
        },
        "process_creation": {
            "product": "windows",
            "category": "process_creation",
            "field": "CommandLine",
        },
        "module": {
            "product": "windows",
            "service": "powershell",
            "definition": "Requirements: Module Logging (Event ID 4103) enabled",
            "field": "Payload",
        },
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
        Synthesizes a standardized, well-formed Sigma YAML detection rule.
        """
        opts = options or RuleSynthesisOptions()
        meta = metadata or self._create_default_metadata(indicators, opts)

        logsource_key = opts.sigma_logsource.lower()
        logsource_cfg = self.LOGSOURCE_CONFIGS.get(logsource_key, self.LOGSOURCE_CONFIGS["scriptblock"])
        field_name = logsource_cfg["field"]

        # Deterministic UUIDv5 based on rule name & sha256 payload
        rule_uuid = opts.compute_rule_id(f"{meta.rule_name}.{meta.payload_sha256}")

        # Assemble MITRE tags
        tags = self._build_tags(meta, indicators)

        # Assemble selections by indicator category
        selections, selection_keys = self._group_indicators_into_selections(indicators, field_name, opts)

        # Build condition statement
        condition = self._build_condition(selection_keys, logsource_key)

        # Assemble root dictionary structure
        doc: Dict[str, Any] = {
            "title": meta.title,
            "id": rule_uuid,
            "status": meta.status.value,
            "description": meta.description,
            "references": meta.references or ["https://github.com/maya-thorne/powershell-ast-deobfuscator"],
            "author": meta.author,
            "date": meta.date.replace("-", "/"),
            "modified": meta.date.replace("-", "/"),
            "tags": tags,
            "logsource": self._build_logsource_dict(logsource_cfg),
            "detection": {
                **selections,
                "condition": condition,
            },
            "falsepositives": meta.false_positives or [
                "Legitimate administrative PowerShell scripts",
                "Approved internal software deployment tools",
            ],
            "level": meta.severity.value,
        }

        # If process_creation, prepend image selection
        if logsource_key == "process_creation":
            doc["detection"] = {
                "selection_img": {
                    "Image|endswith": [r"\powershell.exe", r"\pwsh.exe"]
                },
                **selections,
                "condition": f"selection_img and ({condition})",
            }

        return self._dump_yaml(doc)

    def validate_structure(self, sigma_yaml: str) -> Tuple[bool, List[str]]:
        """
        Validates core structural components of generated Sigma YAML.
        """
        errors: List[str] = []
        required_keys = ["title:", "id:", "status:", "description:", "logsource:", "detection:", "condition:", "level:"]

        for req in required_keys:
            if req not in sigma_yaml:
                errors.append(f"Missing mandatory Sigma field '{req}'")

        if not re.search(r"id:\s+[0-9a-fA-F\-]{36}", sigma_yaml):
            errors.append("Invalid or missing UUID format in 'id' field")

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
            title="Suspicious Deobfuscated PowerShell Threat Activity",
            description="Detects suspicious PowerShell commands, carved C2 URLs, and AMSI/ETW defense evasion patterns.",
            author=options.custom_author or "PowerShell AST Threat Hunter",
            version="1.0.0",
            severity=severity,
            mitre_attack_ids=sorted(list(all_techniques)),
        )

    def _build_tags(self, meta: RuleMetadata, indicators: List[ThreatIndicator]) -> List[str]:
        """Constructs standardized MITRE ATT&CK Sigma tags."""
        tags_set: Set[str] = {
            "attack.execution",
            "attack.t1059.001",
        }

        for tid in meta.mitre_attack_ids:
            tags_set.add(MitreAttackCatalog.format_tag(tid))

        for ind in indicators:
            for tid in ind.mitre_techniques:
                tags_set.add(MitreAttackCatalog.format_tag(tid))

        return sorted(list(tags_set))

    def _build_logsource_dict(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Creates logsource block."""
        res: Dict[str, Any] = {"product": cfg["product"]}
        if "category" in cfg:
            res["category"] = cfg["category"]
        if "service" in cfg:
            res["service"] = cfg["service"]
        if "definition" in cfg:
            res["definition"] = cfg["definition"]
        return res

    def _group_indicators_into_selections(
        self,
        indicators: List[ThreatIndicator],
        field_name: str,
        options: RuleSynthesisOptions,
    ) -> Tuple[Dict[str, Dict[str, List[str]]], List[str]]:
        """Groups indicators by functional category into Sigma selection blocks."""
        category_map: Dict[str, List[str]] = {
            "selection_c2": [],
            "selection_evasion": [],
            "selection_cradle": [],
            "selection_injection": [],
            "selection_suspicious": [],
        }

        # If zero indicators, emit a safe generic fallback
        if not indicators:
            category_map["selection_cradle"].append("DownloadString")

        for ind in indicators:
            # Format value
            val = ind.value.strip()
            if not val or ind.indicator_type == "hex":
                continue

            if ind.category == IndicatorCategory.NETWORK_C2:
                category_map["selection_c2"].append(val)
            elif ind.category == IndicatorCategory.DEFENSE_EVASION:
                category_map["selection_evasion"].append(val)
            elif ind.category == IndicatorCategory.EXECUTION_CRADLE:
                category_map["selection_cradle"].append(val)
            elif ind.category == IndicatorCategory.MEMORY_INJECTION:
                category_map["selection_injection"].append(val)
            else:
                category_map["selection_suspicious"].append(val)

        selections: Dict[str, Dict[str, List[str]]] = {}
        active_keys: List[str] = []

        field_key = f"{field_name}|contains"

        for k, vals in category_map.items():
            if vals:
                # Deduplicate and sort values
                unique_vals = sorted(list(set(vals)))
                selections[k] = {field_key: unique_vals}
                active_keys.append(k)

        return selections, active_keys

    def _build_condition(self, active_keys: List[str], logsource: str) -> str:
        """Synthesizes high-fidelity detection condition logic."""
        if not active_keys:
            return "1 of selection_*"

        has_c2 = "selection_c2" in active_keys
        has_evas = "selection_evasion" in active_keys
        has_cradle = "selection_cradle" in active_keys
        has_inj = "selection_injection" in active_keys

        clauses: List[str] = []

        if has_c2:
            clauses.append("selection_c2")

        if has_evas and has_cradle:
            clauses.append("(selection_evasion and selection_cradle)")
        elif has_evas and has_inj:
            clauses.append("(selection_evasion and selection_injection)")

        if len(active_keys) > 1:
            clauses.append(f"1 of selection_*")

        if clauses:
            return " or ".join(clauses)
        return "1 of selection_*"

    def _dump_yaml(self, data: Any, indent: int = 0) -> str:
        """
        Pure-Python YAML serializer guaranteeing deterministic 2-space indentation,
        proper string quoting, and zero external dependency footprint.
        """
        lines: List[str] = []
        prefix = "  " * indent

        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{prefix}{k}:")
                    lines.append(self._dump_yaml(v, indent + 1))
                else:
                    val_str = self._format_yaml_scalar(v)
                    lines.append(f"{prefix}{k}: {val_str}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    lines.append(f"{prefix}-")
                    lines.append(self._dump_yaml(item, indent + 1))
                else:
                    val_str = self._format_yaml_scalar(item)
                    lines.append(f"{prefix}- {val_str}")
        else:
            lines.append(f"{prefix}{self._format_yaml_scalar(data)}")

        return "\n".join(lines)

    def _format_yaml_scalar(self, val: Any) -> str:
        """Formats scalar values for YAML output with appropriate quoting."""
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, (int, float)):
            return str(val)

        text = str(val)

        # Check if single or double quotes are required
        special_chars = [":", "#", "@", "`", "|", ">", "[", "]", "{", "}", "%", "*", "&", "!", "?"]
        needs_quotes = any(c in text for c in special_chars) or text.strip() != text or "\n" in text

        if needs_quotes or text == "" or text.isdigit():
            # Escape single quotes by doubling them
            escaped = text.replace("'", "''")
            return f"'{escaped}'"
        return text
