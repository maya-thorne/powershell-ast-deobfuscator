"""
Data models, enumerations, and metadata catalogs for YARA and Sigma threat hunting rule synthesis.
Defines threat indicators, MITRE ATT&CK taxonomies, rule metadata, and synthesis options.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional, Tuple


class IndicatorCategory(str, Enum):
    """Classification categories for extracted PowerShell threat indicators."""

    NETWORK_C2 = "network_c2"
    DEFENSE_EVASION = "defense_evasion"
    EXECUTION_CRADLE = "execution_cradle"
    MEMORY_INJECTION = "memory_injection"
    PERSISTENCE = "persistence"
    CRYPTO_OBFUSCATION = "crypto_obfuscation"
    SUSPICIOUS_API = "suspicious_api"
    TARGET_IDENTIFIER = "target_identifier"


class RuleSeverity(str, Enum):
    """Severity tier for generated threat hunting rules."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class RuleStatus(str, Enum):
    """Deployment lifecycle status for Sigma and YARA rules."""

    EXPERIMENTAL = "experimental"
    TEST = "test"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"


@dataclass
class ThreatIndicator:
    """
    Represents an atomic extracted indicator of compromise (IoC) or behavioral threat pattern.
    """

    category: IndicatorCategory
    value: str
    indicator_type: str  # text, hex, regex, url, ip, cmdlet, member, api
    weight: float  # 1.0 to 10.0 scale of specificity and hunting fidelity
    description: str
    mitre_techniques: List[str] = field(default_factory=list)
    raw_match: Optional[str] = None
    is_deobfuscated_only: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes threat indicator to JSON-serializable dictionary."""
        return {
            "category": self.category.value if isinstance(self.category, IndicatorCategory) else str(self.category),
            "value": self.value,
            "indicator_type": self.indicator_type,
            "weight": self.weight,
            "description": self.description,
            "mitre_techniques": list(self.mitre_techniques),
            "raw_match": self.raw_match,
            "is_deobfuscated_only": self.is_deobfuscated_only,
            "metadata": self.metadata,
        }


class MitreAttackCatalog:
    """
    Curated MITRE ATT&CK technique catalog mapping PowerShell threats to Enterprise Matrix IDs.
    """

    TECHNIQUES: Dict[str, Tuple[str, str]] = {
        "T1059.001": ("Command and Scripting Interpreter: PowerShell", "execution"),
        "T1562.001": ("Impair Defenses: Disable or Modify Tools", "defense-evasion"),
        "T1027": ("Obfuscated Files or Information", "defense-evasion"),
        "T1027.005": ("Indicator Removal from Tools", "defense-evasion"),
        "T1105": ("Ingress Tool Transfer", "command-and-control"),
        "T1055": ("Process Injection", "privilege-escalation"),
        "T1071.001": ("Application Layer Protocol: Web Protocols", "command-and-control"),
        "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "persistence"),
        "T1053.005": ("Scheduled Task/Job: Scheduled Task", "persistence"),
        "T1546.004": ("Event Triggered Execution: WMI Event Subscription", "persistence"),
        "T1082": ("System Information Discovery", "discovery"),
        "T1086": ("PowerShell Execution (Legacy)", "execution"),
    }

    @classmethod
    def get_info(cls, technique_id: str) -> Tuple[str, str]:
        """Returns (technique_name, tactic) for given MITRE technique ID."""
        return cls.TECHNIQUES.get(technique_id, ("Unknown Technique", "general"))

    @classmethod
    def format_tag(cls, technique_id: str) -> str:
        """Formats MITRE technique ID into Sigma-standard tag notation (e.g. attack.t1562.001)."""
        clean_id = technique_id.lower().replace(".", ".")
        return f"attack.{clean_id}"


@dataclass
class RuleMetadata:
    """
    Standardized metadata header for generated YARA and Sigma threat hunting rules.
    """

    rule_name: str
    title: str
    description: str
    author: str = "Threat Hunting Analyst"
    date: str = "2026-10-16"
    version: str = "1.0.0"
    severity: RuleSeverity = RuleSeverity.HIGH
    status: RuleStatus = RuleStatus.EXPERIMENTAL
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    mitre_attack_ids: List[str] = field(default_factory=list)
    payload_sha256: str = ""
    false_positives: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes rule metadata to dictionary."""
        return {
            "rule_name": self.rule_name,
            "title": self.title,
            "description": self.description,
            "author": self.author,
            "date": self.date,
            "version": self.version,
            "severity": self.severity.value if isinstance(self.severity, RuleSeverity) else str(self.severity),
            "status": self.status.value if isinstance(self.status, RuleStatus) else str(self.status),
            "references": self.references,
            "tags": self.tags,
            "mitre_attack_ids": self.mitre_attack_ids,
            "payload_sha256": self.payload_sha256,
            "false_positives": self.false_positives,
        }


@dataclass
class RuleSynthesisOptions:
    """
    Configuration options controlling the dynamic synthesis of YARA and Sigma rules.
    """

    target_scope: str = "deobfuscated"  # "deobfuscated", "raw", "dual"
    min_weight: float = 3.0  # Minimum specificity threshold for extracted indicators
    max_strings: int = 25  # Maximum number of string patterns to include in YARA rule
    yara_condition_style: str = "balanced"  # "balanced", "strict", "loose", "categorized"
    filesize_limit: Optional[str] = "2MB"  # YARA filesize condition
    sigma_logsource: str = "scriptblock"  # "scriptblock", "process_creation", "module"
    include_metadata: bool = True
    custom_author: Optional[str] = None
    custom_rule_id: Optional[str] = None
    yara_ascii: bool = True
    yara_wide: bool = True
    yara_nocase: bool = True

    def compute_rule_id(self, base_str: str) -> str:
        """
        Computes a deterministic UUIDv5 identifier for Sigma rules based on payload content.
        """
        if self.custom_rule_id:
            return self.custom_rule_id
        import uuid

        namespace = uuid.NAMESPACE_DNS
        return str(uuid.uuid5(namespace, f"sigma.powershell.hunt.{base_str}"))
