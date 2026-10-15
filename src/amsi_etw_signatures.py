"""
PowerShell AMSI & ETW Bypass Signatures and Ruleset Engine.
Defines catalogued detection rules, category hierarchies, severity tiers,
and finding models for in-memory patching and reflection tampering.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class BypassCategory(str, Enum):
    """Categorization of AMSI & ETW evasion vectors."""
    MEMORY_PATCH = "memory_patch"
    REFLECTION_TAMPERING = "reflection_tampering"
    COM_HIJACK = "com_hijack"
    CONTEXT_CORRUPTION = "context_corruption"
    LOGGING_SUPPRESSION = "logging_suppression"


class TargetSystem(str, Enum):
    """Target defense or telemetry subsystem being evaded."""
    AMSI = "amsi"
    ETW = "etw"
    SCRIPT_LOGGING = "script_logging"
    WLDP = "wldp"


class BypassSeverity(str, Enum):
    """Severity tier based on potential impact and defense blinding."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class BypassSignature:
    """Detection signature definition for AMSI/ETW bypass methods."""
    id: str
    name: str
    category: BypassCategory
    target_system: TargetSystem
    severity: BypassSeverity
    description: str
    mitre_id: str = "T1562.001"
    target_symbols: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    patch_byte_signatures: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "target_system": self.target_system.value,
            "severity": self.severity.value,
            "description": self.description,
            "mitre_id": self.mitre_id,
            "target_symbols": self.target_symbols,
            "indicators": self.indicators,
            "patch_byte_signatures": self.patch_byte_signatures,
        }


@dataclass
class AmsiEtwFinding:
    """Forensic finding emitted when an AMSI/ETW bypass pattern is identified."""
    signature_id: str
    signature_name: str
    category: BypassCategory
    target_system: TargetSystem
    severity: BypassSeverity
    mitre_id: str
    confidence: float
    matched_text: str
    description: str
    line_number: Optional[int] = None
    target_symbol: Optional[str] = None
    neutralizable: bool = True
    start_pos: Optional[int] = None
    end_pos: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "signature_id": self.signature_id,
            "signature_name": self.signature_name,
            "category": self.category.value,
            "target_system": self.target_system.value,
            "severity": self.severity.value,
            "mitre_id": self.mitre_id,
            "confidence": round(self.confidence, 3),
            "line_number": self.line_number,
            "target_symbol": self.target_symbol,
            "matched_text": self.matched_text,
            "description": self.description,
            "neutralizable": self.neutralizable,
        }
        if self.start_pos is not None:
            d["start_pos"] = self.start_pos
        if self.end_pos is not None:
            d["end_pos"] = self.end_pos
        return d



class AmsiEtwRuleSet:
    """
    Registry and query catalog for AMSI and ETW bypass signatures.
    Supports filtering by target system, category, and severity.
    """

    def __init__(self, signatures: Optional[List[BypassSignature]] = None) -> None:
        self._signatures: Dict[str, BypassSignature] = {}
        if signatures:
            for sig in signatures:
                self.register(sig)

    def register(self, signature: BypassSignature) -> None:
        self._signatures[signature.id] = signature

    def get(self, signature_id: str) -> Optional[BypassSignature]:
        return self._signatures.get(signature_id)

    def all_signatures(self) -> List[BypassSignature]:
        return list(self._signatures.values())

    def by_target(self, target: TargetSystem) -> List[BypassSignature]:
        return [s for s in self._signatures.values() if s.target_system == target]

    def by_category(self, category: BypassCategory) -> List[BypassSignature]:
        return [s for s in self._signatures.values() if s.category == category]

    def by_severity(self, severity: BypassSeverity) -> List[BypassSignature]:
        return [s for s in self._signatures.values() if s.severity == severity]

    def __len__(self) -> int:
        return len(self._signatures)


# -----------------------------------------------------------------------------
# Curated Standard Bypass Signatures Catalog
# -----------------------------------------------------------------------------

BUILTIN_SIGNATURES: List[BypassSignature] = [
    # 1. AmsiScanBuffer Memory Patch
    BypassSignature(
        id="AMSI-MEM-001",
        name="AmsiScanBuffer Memory Patching",
        category=BypassCategory.MEMORY_PATCH,
        target_system=TargetSystem.AMSI,
        severity=BypassSeverity.CRITICAL,
        description="Patches the prologue or body of amsi.dll!AmsiScanBuffer in memory via VirtualProtect and Marshal.Copy or WriteProcessMemory.",
        mitre_id="T1562.001",
        target_symbols=["AmsiScanBuffer", "amsi.dll"],
        indicators=[
            "amsiscanbuffer",
            "amsi.dll",
            "virtualprotect",
            "marshal]::copy",
            "writeprocessmemory",
        ],
        patch_byte_signatures=["c3", "b857000780c3", "31c0c3", "b801000000c3"],
    ),
    # 2. AmsiInitialize / AmsiOpenSession Memory Patch
    BypassSignature(
        id="AMSI-MEM-002",
        name="AmsiInitialize / AmsiOpenSession Memory Patching",
        category=BypassCategory.MEMORY_PATCH,
        target_system=TargetSystem.AMSI,
        severity=BypassSeverity.CRITICAL,
        description="Patches AmsiInitialize or AmsiOpenSession in amsi.dll to corrupt provider session creation.",
        mitre_id="T1562.001",
        target_symbols=["AmsiInitialize", "AmsiOpenSession", "amsi.dll"],
        indicators=[
            "amsiinitialize",
            "amsiopensession",
            "amsi.dll",
            "virtualprotect",
        ],
        patch_byte_signatures=["c3", "31c0c3"],
    ),
    # 3. EtwEventWrite Memory Patch
    BypassSignature(
        id="ETW-MEM-001",
        name="EtwEventWrite Memory Patching",
        category=BypassCategory.MEMORY_PATCH,
        target_system=TargetSystem.ETW,
        severity=BypassSeverity.CRITICAL,
        description="Overwrites ntdll.dll!EtwEventWrite with ret opcode (0xC3 or 0xC2, 0x14, 0x00) to blind ETW event tracing and ScriptBlock logging.",
        mitre_id="T1562.001",
        target_symbols=["EtwEventWrite", "ntdll.dll"],
        indicators=[
            "etweventwrite",
            "ntdll.dll",
            "virtualprotect",
            "marshal]::copy",
        ],
        patch_byte_signatures=["c3", "c21400", "31c0c3"],
    ),
    # 4. EtwEventWriteTransfer / EtwEventWriteString Patch
    BypassSignature(
        id="ETW-MEM-002",
        name="EtwEventWriteTransfer / EtwEventWriteString Memory Patching",
        category=BypassCategory.MEMORY_PATCH,
        target_system=TargetSystem.ETW,
        severity=BypassSeverity.CRITICAL,
        description="Patches EtwEventWriteTransfer or EtwEventWriteString in ntdll.dll to prevent event delivery.",
        mitre_id="T1562.001",
        target_symbols=["EtwEventWriteTransfer", "EtwEventWriteString", "ntdll.dll"],
        indicators=[
            "etweventwritetransfer",
            "etweventwritestring",
            "ntdll.dll",
            "virtualprotect",
        ],
        patch_byte_signatures=["c3", "31c0c3"],
    ),
    # 5. amsiInitFailed Reflection Tampering
    BypassSignature(
        id="AMSI-REFL-001",
        name="amsiInitFailed Reflection Tampering",
        category=BypassCategory.REFLECTION_TAMPERING,
        target_system=TargetSystem.AMSI,
        severity=BypassSeverity.CRITICAL,
        description="Reflectively forces AmsiUtils.amsiInitFailed to $true to skip AMSI scanning on all subsequent inputs.",
        mitre_id="T1562.001",
        target_symbols=["amsiInitFailed", "AmsiUtils"],
        indicators=[
            "amsiinitfailed",
            "amsiutils",
            "system.management.automation.amsiutils",
        ],
    ),
    # 6. amsiContext Reflection Corruption
    BypassSignature(
        id="AMSI-REFL-002",
        name="amsiContext Reflection Corruption",
        category=BypassCategory.CONTEXT_CORRUPTION,
        target_system=TargetSystem.AMSI,
        severity=BypassSeverity.HIGH,
        description="Reflectively sets AmsiUtils.amsiContext to 0 or [IntPtr]::Zero or corrupts memory buffer header.",
        mitre_id="T1562.001",
        target_symbols=["amsiContext", "AmsiUtils"],
        indicators=[
            "amsicontext",
            "amsiutils",
            "[intptr]::zero",
        ],
    ),
    # 7. PSEtwLogProvider.etwProvider Reflection Tampering
    BypassSignature(
        id="ETW-REFL-001",
        name="PSEtwLogProvider.etwProvider Reflection Tampering",
        category=BypassCategory.REFLECTION_TAMPERING,
        target_system=TargetSystem.ETW,
        severity=BypassSeverity.HIGH,
        description="Reflectively accesses PSEtwLogProvider.etwProvider and sets it to $null to suppress PowerShell ETW logging.",
        mitre_id="T1562.001",
        target_symbols=["etwProvider", "PSEtwLogProvider"],
        indicators=[
            "psetwlogprovider",
            "etwprovider",
            "system.management.automation.tracing.psetwlogprovider",
        ],
    ),
    # 8. EventProvider.m_enabled Reflection Tampering
    BypassSignature(
        id="ETW-REFL-002",
        name="EventProvider.m_enabled Reflection Tampering",
        category=BypassCategory.REFLECTION_TAMPERING,
        target_system=TargetSystem.ETW,
        severity=BypassSeverity.HIGH,
        description="Tampering with EventProvider's private field m_enabled, setting it to 0 or $false to disable ETW emission.",
        mitre_id="T1562.001",
        target_symbols=["m_enabled", "EventProvider"],
        indicators=[
            "m_enabled",
            "eventprovider",
            "system.diagnostics.eventing.eventprovider",
        ],
    ),
    # 9. cachedGroupPolicySettings Reflection Tampering
    BypassSignature(
        id="LOG-REFL-001",
        name="cachedGroupPolicySettings Reflection Tampering",
        category=BypassCategory.LOGGING_SUPPRESSION,
        target_system=TargetSystem.SCRIPT_LOGGING,
        severity=BypassSeverity.HIGH,
        description="Reflectively tampers with System.Management.Automation.Utils.cachedGroupPolicySettings dictionary to silence ScriptBlockLogging.",
        mitre_id="T1562.001",
        target_symbols=["cachedGroupPolicySettings", "EnableScriptBlockLogging"],
        indicators=[
            "cachedgrouppolicysettings",
            "scriptblocklogging",
            "enablescriptblocklogging",
            "system.management.automation.utils",
        ],
    ),
    # 10. WLDP Dynamic Code Trust Memory Patching
    BypassSignature(
        id="WLDP-MEM-001",
        name="WLDP QueryDynamicCodeTrust Memory Patching",
        category=BypassCategory.MEMORY_PATCH,
        target_system=TargetSystem.WLDP,
        severity=BypassSeverity.HIGH,
        description="Patches WldpQueryDynamicCodeTrust or WldpIsClassInApprovedList in wldp.dll.",
        mitre_id="T1562.001",
        target_symbols=["WldpQueryDynamicCodeTrust", "wldp.dll"],
        indicators=[
            "wldpquerydynamiccodetrust",
            "wldpisclassinapprovedlist",
            "wldp.dll",
            "virtualprotect",
        ],
        patch_byte_signatures=["c3", "31c0c3"],
    ),
]


DEFAULT_RULESET = AmsiEtwRuleSet(BUILTIN_SIGNATURES)
